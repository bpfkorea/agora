/*******************************************************************************

    Implementation of the Validator API.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.node.Validator;

import agora.api.Validator;
import agora.common.Amount;
import agora.common.Config;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Params;
import agora.consensus.data.PreImageInfo;
import agora.consensus.data.Transaction;
import agora.consensus.data.ValidatorBlockSig;
import agora.consensus.EnrollmentManager;
import agora.consensus.protocol.Data;
import agora.consensus.protocol.Nominator;
import agora.consensus.Quorum;
import agora.consensus.state.UTXOSet;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.network.Clock;
import agora.network.Manager;
import agora.node.admin.AdminInterface;
import agora.node.BlockStorage;
import agora.node.FullNode;
import agora.node.Ledger;
import agora.registry.API;
import agora.utils.Log;
import agora.utils.PrettyPrinter;

import scpd.types.Stellar_SCP;

import std.algorithm : each;

import core.stdc.stdlib : abort;
import core.time;

/*******************************************************************************

    Implementation of the Validator node

    This class implement the business code of the node.
    Communication with the other nodes is handled by the `Network` class.

*******************************************************************************/

public class Validator : FullNode, API
{
    /// Nominator instance
    protected Nominator nominator;

    /// The current required set of peers UTXOs to connect to
    protected UTXO[Hash] required_peer_utxos;

    /// Currently active quorum configuration
    protected QuorumConfig qc;

    /// Quorum generator parameters
    protected QuorumParams quorum_params;

    /// The last height at which a quorum shuffle took place.
    /// If a new block is externalized and `last_shuffle_height`
    /// is >= `QuorumShuffleInterval` then the quorum will be reshuffled again.
    private Height last_shuffle_height = Height(0);

    /// Workaround: onRegenerateQuorums() is called from within the ctor,
    /// but LocalScheduler is not instantiated yet.
    private bool started;

    /// Ctor
    public this (Config config)
    {
        assert(config.validator.enabled);
        super(config);
        this.quorum_params = QuorumParams(this.params.MaxQuorumNodes,
            this.params.QuorumThreshold);

        auto vledger = new ValidatingLedger(this.params, this.engine,
            this.utxo_set, this.storage, this.enroll_man, this.pool,
            this.fee_man, this.clock, config.node.block_time_offset_tolerance,
            &this.onAcceptedBlock);
        this.ledger = vledger;

        this.nominator = this.makeNominator(
            this.clock, this.network, vledger, this.enroll_man, this.taskman);
        this.nominator.onInvalidNomination = &this.invalidNominationHandler;

        // Make sure our ValidatorSet has our pre-image
        // This is especially important on initialization, as replaying blocks
        // does not call `onAcceptedBlock`.
        PreImageInfo self;
        if (this.ledger.enrollment_manager.getNextPreimage(self, this.ledger.getBlockHeight()))
            this.ledger.enrollment_manager.addPreimage(self);

        // currently we are not saving preimage info,
        // we only have the commitment in the genesis block
        this.regenerateQuorums(this.ledger.getBlockHeight());
    }

    /***************************************************************************

        Called when the active validator set has changed after a block
        was externalized.

        Regenerates the quorum set config and updates the Nominator
        with the new quorum set.

        The background network discovery task will automatically attempt to
        find the Validator nodes in the quorum set configuration and connect
        to them.

        Params:
            height = the height at which the validator set changed.
                     Note that it may be different to 'ledger.getBlockHeight()'
                     when the node is booting up for the first time as we
                     currently only have commitment info from GenesisBlock,
                     and lack preimages.

    ***************************************************************************/

    private void regenerateQuorums (Height height) nothrow @safe
    {
        this.last_shuffle_height = height;

        // we're not enrolled and don't care about quorum sets
        if (!this.enroll_man.isEnrolled(height + 1, &this.utxo_set.peekUTXO))
        {
            this.nominator.stopNominatingTimer();
            this.qc = QuorumConfig.init;
            return;
        }

        // We get the enrollment key for this validator.
        auto this_utxo = this.enroll_man.getEnrollmentKey();

        Hash[] utxo_keys;
        // We add one to height as we are interested in enrolled at next block
        if (!this.enroll_man.getEnrolledUTXOs(height + 1, utxo_keys) ||
            utxo_keys.length == 0)
        {
            log.fatal("Could not retrieve enrollments / no enrollments found");
            assert(0);
        }

        // We create new SCP object if the enrollment key is changed.
        this.nominator.createSCPObject();

        static QuorumConfig[] other_qcs;
        this.rebuildQuorumConfig(this.qc, other_qcs, this_utxo, utxo_keys, height);
        this.nominator.setQuorumConfig(this.qc, other_qcs);
        buildRequiredKeys(this_utxo, this.qc, utxo_keys,
            &this.utxo_set.peekUTXO, this.required_peer_utxos);

        if (this.started)
            this.nominator.startNominatingTimer();
    }

    /***************************************************************************

        Generate the quorum configuration for this node and all other validator
        nodes in the network, based on the blockchain state (enrollments).

        Params:
            qc = will contain the quorum configuration
            other_qcs = will contain the list of other nodes' quorum configs.
            filter_utxo = the UTXO to filter out (UTXO of the self node)
            utxos = The UTXO hashes of all the validators
            height = current block height

    ***************************************************************************/

    private void rebuildQuorumConfig (ref QuorumConfig qc,
        ref QuorumConfig[] other_qcs, in Hash filter_utxo, in Hash[] utxos,
        Height height) nothrow @safe
    {
        import std.algorithm;
        import std.array;

        try
        {
            // We take random seed from last block as next is not available yet
            // In the fast path, this is called immediately after a block has been
            // externalized, so we can simply use the Ledger. Otherwise we need
            // to run from storage.
            auto self_enroll = this.enroll_man.getEnrollmentKey();
            const rand_seed = this.ledger.getBlockHeight() == height ?
                this.ledger.getLastBlock().header.random_seed :
                this.ledger.getBlocksFrom(height).front.header.random_seed;
            qc = buildQuorumConfig(self_enroll, utxos, this.utxo_set.getUTXOFinder(),
                rand_seed, this.quorum_params);

            other_qcs.length = 0;
            () @trusted { assumeSafeAppend(other_qcs); }();

            foreach (utxo; utxos.filter!(
                utxo => utxo != filter_utxo))  // skip our own
            {
                other_qcs ~= buildQuorumConfig(utxo, utxos,
                    this.utxo_set.getUTXOFinder(), rand_seed, this.quorum_params);
            }
        }
        catch (Exception e)
        {
            log.fatal("rebuildQuorumConfig: Exception thrown: {}", e);
            assert(0);
        }
    }

    /***************************************************************************

        Begins asynchronous tasks for node discovery and periodic catchup.

    ***************************************************************************/

    public override void start ()
    {
        this.started = true;
        // Note: Switching the next two lines leads to test failure
        // It should not, and this needs to be fixed eventually
        if (auto timer = this.network.startPeriodicNameRegistration())
            this.timers ~= timer;
        super.start();

        this.clock.startSyncing();
        this.timers ~= this.taskman.setTimer(
            this.config.validator.preimage_reveal_interval,
            &this.onPreImageRevealTimer, Periodic.Yes);

        if (this.enroll_man.isEnrolled(this.ledger.getBlockHeight() + 1, &this.utxo_set.peekUTXO))
            this.nominator.startNominatingTimer();
        if (this.config.validator.recurring_enrollment)
            this.checkAndEnroll(this.ledger.getBlockHeight());

        this.timers ~= this.taskman.setTimer(config.validator.preimage_catchup_interval, () {this.network.retrievePreimages(ledger);}, Periodic.Yes);
    }

    /// Ditto
    protected override void discoveryTask ()
    {
        this.network.discover(this.required_peer_utxos);
    }

    ///
    public override Identity handshake (PublicKey peer)
    {
        return this.getPublicKey(peer);
    }

    /// GET /public_key
    public override Identity getPublicKey (PublicKey key = PublicKey.init) nothrow @safe
    {
        import agora.flash.OnionPacket : generateSharedSecret;
        import libsodium.crypto_auth;

        this.recordReq("public_key");

        Identity id = Identity(this.config.validator.key_pair.address,
                               this.enroll_man.getEnrollmentKey());
        if (key == PublicKey.init)
            return id;

        Hash shared_sec = generateSharedSecret(false,
            this.config.validator.key_pair.secret, key).hashFull();
        static assert(shared_sec.sizeof >= crypto_auth_KEYBYTES);

        id.mac.length = crypto_auth_BYTES;
        () @trusted { crypto_auth (id.mac.ptr, id.key[].ptr,
            id.key[].length, shared_sec[].ptr); } ();
        return id;
    }

    /***************************************************************************

        Receive an SCP envelope.

        API:
            PUT /envelope

        Params:
            envelope = the SCP envelope

    ***************************************************************************/

    public override void receiveEnvelope (SCPEnvelope envelope) @safe
    {
        this.recordReq("receive_envelope");
        this.nominator.receiveEnvelope(envelope);
    }

    /***************************************************************************

        Receive a block signature.

        API:
            PUT /block_sig

        Params:
            block_sig = the block signature of a validator (part of multisig)

    ***************************************************************************/

    public override void receiveBlockSignature (ValidatorBlockSig block_sig) @safe
    {
        this.recordReq("receive_block_signature");
        this.nominator.receiveBlockSignature(block_sig);
    }

    /// Returns: The Logger to use for this class
    protected override Logger makeLogger ()
    {
        return Logger(this.config.validator.key_pair.address.toString());
    }

    /***************************************************************************

        Returns an instance of a Nominator.

        Test-suites can inject a badly-behaved nominator in order to
        simulate byzantine nodes.

        Params:
            clock = Clock instance
            network = the network manager for gossiping SCPEnvelopes
            ledger = Ledger instance
            enroll_man = Enrollment manager
            taskman = the task manager

        Returns:
            An instance of a `Nominator`

    ***************************************************************************/

    protected Nominator makeNominator (Clock clock, NetworkManager network,
        ValidatingLedger ledger, EnrollmentManager enroll_man, ITaskManager taskman)
    {
        return new Nominator(
            this.params, this.config.validator.key_pair, clock, network, ledger,
            enroll_man, taskman, this.cacheDB,
            this.config.validator.nomination_interval, &this.acceptBlock);
    }

    /***************************************************************************

        Get a Clock instance. May be overriden in unittests to
        simulate clock disparities, as well as provide a custom
        median retrieveal delegate to simulate delays (task.wait() calls).

        Params:
            taskman = task manager used to spawn timers

        Returns:
            a Clock instance

    ***************************************************************************/

    protected override Clock makeClock (ITaskManager taskman)
    {
        return new Clock((out long time_offset)
            {
                return this.network.getNetTimeOffset(this.qc.threshold,
                    time_offset);
            },
            (Duration duration, void delegate() cb) nothrow @trusted
                { this.timers ~= this.taskman.setTimer(duration, cb, Periodic.Yes); });
    }

    /***************************************************************************

        Instantiate a new instance of the Admin interface

        This function needs to be called after the node is fully set-up.

    ***************************************************************************/

    public AdminInterface makeAdminInterface ()
    {
        return new AdminInterface(this.config.validator.key_pair, this.clock,
            this.enroll_man);
    }

    /***************************************************************************

        Calls the base class `onAcceptedBlock` and additionally
        shuffles the quorum set if the new block header height
        is `QuorumShuffleInterval` blocks newer than the last
        shuffle height.

        Params:
            block = the block which was added to the ledger

    ***************************************************************************/

    protected override void onAcceptedBlock (in Block block,
        bool validators_changed) @safe
    {
        assert(block.header.height >= this.last_shuffle_height);

        // block received either via externalize or getBlocksFrom(),
        // we need to cancel any existing nominating rounds.
        this.nominator.stopNominationRound(block.header.height);

        const need_shuffle = block.header.height >=
            (this.last_shuffle_height + this.params.QuorumShuffleInterval);

        // regenerate the quorums
        if (validators_changed || need_shuffle)
            this.regenerateQuorums(block.header.height);

        // Re-enroll if our enrollment is about to expire and the block is recent enough
        auto cur_offset = this.clock.networkTime() - this.params.GenesisTimestamp;
        if (this.config.validator.recurring_enrollment &&
            block.header.time_offset > cur_offset - 3 * this.params.BlockInterval.total!"seconds")
            this.checkAndEnroll(block.header.height);

        // FIXME: Add our pre-image to the validator set so that `getValidators`
        // works as expected. This will need to be fixed in the Ledger in the
        // future, as `onPreImageRevealTimer` has some issues, but doing it here
        // allows us to unify usage of `getValidators`.
        PreImageInfo self;
        if (this.ledger.enrollment_manager.getNextPreimage(self, block.header.height))
            this.ledger.enrollment_manager.addPreimage(self);

        // note: may context switch, should be called last after quorums
        // are regenerated above.
        super.onAcceptedBlock(block, validators_changed);
    }

    /***************************************************************************

        Build the list of required quorum peers to connect to

        Supports recalling `sub_quorums` config structures.

        Params:
            filter_utxo = the UTXO to filter out (UTXO of the self node)
            quorum_conf = The SCP quorum set configuration
            utxos = The UTXO hashes of all the validators
            peekUTXO = An `UTXOFinder` without replay-protection
            nodes = Will contain the set of public keys to connect to

    ***************************************************************************/

    private static void buildRequiredKeys (in Hash filter_utxo,
        in QuorumConfig quorum_conf, in Hash[] utxos,
        scope UTXOFinder peekUTXO, ref UTXO[Hash] nodes)
        @safe nothrow
    {
        import std.algorithm;

        foreach (utxo; utxos.filter!(utxo => utxo != filter_utxo))
        {
            UTXO utxo_value;
            assert(peekUTXO(utxo, utxo_value));
            nodes[utxo] = utxo_value;
        }

        foreach (sub_conf; quorum_conf.quorums)
            buildRequiredKeys(filter_utxo, sub_conf, utxos, peekUTXO, nodes);
    }

    /***************************************************************************

        Periodically called to perform pre-images revelation.

        Increase the next reveal height by revelation period if necessary.

    ***************************************************************************/

    protected void onPreImageRevealTimer () @safe
    {
        PreImageInfo preimage;
        if (this.enroll_man.getNextPreimage(preimage,
            this.ledger.getBlockHeight()))
        {
            this.enroll_man.addPreimage(preimage);
            this.network.peers.each!(p => p.client.sendPreimage(preimage));
            this.pushPreImage(preimage);
        }
    }

    /***************************************************************************

        Calls the base class `shutdown` and store the latest SCP state

    ***************************************************************************/

    override void shutdown ()
    {
        super.shutdown();
        this.nominator.stopNominatingTimer();
        this.nominator.storeLatestState();
    }

    /***************************************************************************

        Check if the next enrollment is available or validator is not enrolled.
        Enroll when necessary.

        Params:
            height = Current block height

        Returns:
            The `Enrollment` used to enroll with, or `Enrollment.init`
            if not enrolled

    ***************************************************************************/

    protected Enrollment checkAndEnroll (Height height) @safe
    {
        auto next_height = height + 1;
        Hash enroll_key = this.enroll_man.getEnrolledUTXO(height,
            this.utxo_set.getUTXOFinder());

        if (enroll_key == Hash.init &&
            (enroll_key = this.getFrozenUTXO()) == Hash.init)
            return Enrollment.init; // Not enrolled and no frozen UTXO

        const enrolled = this.enroll_man.validator_set.getEnrolledHeight(next_height, enroll_key);

        // This validators enrollment will expire next cycle or not enrolled at all
        const avail_height = enrolled == ulong.max ?
                                next_height : enrolled + this.params.ValidatorCycle;

        const enrollment = this.enroll_man.createEnrollment(enroll_key, avail_height);
        log.trace("Sending Enrollment for enrolling at height {} (to validate blocks {} to {})",
            avail_height, avail_height + 1, avail_height + this.params.ValidatorCycle);
        this.enroll_man.enroll_pool.addValidated(enrollment, avail_height);
        this.network.peers.each!(p => p.client.sendEnrollment(enrollment));
        return enrollment;
    }

    /***************************************************************************

        Get a frozen UTXO owned by the Validator

        Return:
            Returns hash of a UTXO eligible for staking

    ***************************************************************************/

    private Hash getFrozenUTXO () @safe
    {
        const pub_key = this.config.validator.key_pair.address;
        foreach (key, utxo; this.utxo_set.getUTXOs(pub_key))
        {
            if (utxo.output.type == OutputType.Freeze &&
                utxo.output.value.integral() >= Amount.MinFreezeAmount.integral())
                return key;
        }

        return Hash.init;
    }

    /***************************************************************************

        A delegate to be called by Nominator when node's own nomination is
        invalid

        Params:
            data = Invalid ConsensusData
            msg = Reason

    ***************************************************************************/

    protected void invalidNominationHandler (in ConsensusData data, in string msg)
        @safe
    {
        // Network needs Validators, see if we can enroll
        if (this.config.validator.recurring_enrollment &&
            msg == Ledger.InvalidConsensusDataReason.NotEnoughValidators)
            this.checkAndEnroll(this.ledger.getBlockHeight());
    }
}
