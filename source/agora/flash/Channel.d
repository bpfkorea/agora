/*******************************************************************************

    Contains the Flash Channel definition.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.Channel;

import agora.flash.api.FlashAPI;
import agora.flash.Config;
import agora.flash.ErrorCode;
import agora.flash.OnionPacket;
import agora.flash.Scripts;
import agora.flash.Types;
import agora.flash.UpdateSigner;

import agora.common.Amount;
import agora.common.ManagedDatabase;
import agora.common.Set;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.data.UTXO;
import agora.consensus.data.Transaction;
import agora.crypto.ECC;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.crypto.Schnorr;
import agora.script.Engine;
import agora.script.Lock;
import agora.serialization.Serializer;
import agora.utils.Backoff;
import agora.utils.Log;

import std.array;
import std.algorithm;
import std.conv;
import std.datetime.systime;
import std.exception;
import std.format;
import std.stdio;  // todo: remove
import std.traits;
import std.typecons;

import core.time;

alias LockType = agora.script.Lock.LockType;

mixin AddLogger!();

/// Ditto
public class Channel
{
    /// Used to publish funding / trigger / update / settlement txs to blockchain
    public const void delegate (Transaction) txPublisher;

    /// Database
    private ManagedDatabase db;

    /// The execution engine, used to validate all flash-layer transactions.
    private Engine engine;

    /// Task manager to spawn fibers with
    public ITaskManager taskman;

    /// The peer of the other end of the channel
    public FlashAPI peer;

    /// Global flash configuration (not channel-specific)
    private FlashConfig flash_conf;

    /// All the channel metadata
    mixin ChannelMetadata!() meta;

    /// Serialization buffer
    private ubyte[] serialize_buffer;

    /// The signer for an update / settle pair
    private UpdateSigner update_signer;

    /// Route payments to another channel
    private PaymentRouter paymentRouter;

    /// Called when the channel state has been changed
    private alias OnChannelNotify = void delegate (
        PublicKey key, Hash chan_id, ChannelState state, ErrorCode error) @safe;
    /// Ditto
    private OnChannelNotify onChannelNotify;

    /// When a payment has been completed we need to check whether we know
    /// the matching secret of the payment hash. Then we can propose a new
    /// channel update for the channel which uses this payment hash.
    private alias OnPaymentComplete = void delegate (PublicKey key,
        Hash chan_id, Hash payment_hash, ErrorCode error = ErrorCode.None) @safe;
    /// Ditto
    private OnPaymentComplete onPaymentComplete;

    /// Called when a channel update has been completed.
    private alias OnUpdateComplete = void delegate (
        PublicKey pk, in Hash[] secrets, in Hash[] revert_htlcs);
    /// Ditto
    private OnUpdateComplete onUpdateComplete;

    /// Fetch the Flash Client for the peer
    private FlashAPI delegate (in PublicKey peer_pk, Duration timeout) getFlashClient;

    /// Retry delay algorithm
    private Backoff backoff;


    /***************************************************************************

        Constructor for new channels.

        Params:
            flash_conf = the global flash configuration.
            conf = the static channel configuration.
            kp = the node's key-pair.
            priv_nonce = the nonce that is used for signing the first
                settle & trigger transactions.
            peer_nonce = the peer's public nonce for the first
                settle & trigger transactions.
            peer = a Flash API client instance
            engine = the execution engine
            taskman = used to spawn tasks
            txPublisher = used to publish transactions to the Agora network.
            paymentRouter = used to forward HTLCs to the next hop
            onUpdateComplete = called when a channel update has completed
            db = the database to dump the channel metadata to

    ***************************************************************************/

    public this (FlashConfig flash_conf, ChannelConfig conf, in KeyPair kp,
        PrivateNonce priv_nonce, PublicNonce peer_nonce, FlashAPI peer,
        Engine engine, ITaskManager taskman,
        void delegate (Transaction) txPublisher,
        PaymentRouter paymentRouter,
        OnChannelNotify onChannelNotify,
        OnPaymentComplete onPaymentComplete,
        OnUpdateComplete onUpdateComplete,
        ManagedDatabase db)
    {
        this.flash_conf = flash_conf;
        this.conf = conf;
        this.kp = kp;
        this.is_owner = conf.funder_pk == kp.address;
        this.peer = peer;
        this.peer_pk = this.is_owner ? conf.peer_pk : conf.funder_pk;
        this.db = db;
        this.priv_nonce = priv_nonce;
        this.peer_nonce = peer_nonce;
        this.engine = engine;
        this.taskman = taskman;
        this.txPublisher = txPublisher;
        this.update_signer = new UpdateSigner(this.flash_conf, this.conf,
            this.kp, this.peer_pk, this.engine, this.taskman, db);
        this.paymentRouter = paymentRouter;
        this.onChannelNotify = onChannelNotify;
        this.onPaymentComplete = onPaymentComplete;
        this.onUpdateComplete = onUpdateComplete;
        this.backoff = new Backoff(this.flash_conf.retry_multiplier,
            this.flash_conf.max_retry_delay.total!"msecs".to!uint);

        this.last_update = ChannelUpdate(this.conf.chan_id,
            this.is_owner ? PaymentDirection.TowardsPeer : PaymentDirection.TowardsOwner,
            Amount(1), Amount(1), 1);
        this.last_update.sig = this.kp.sign(this.last_update);

        this.dump();

        this.taskman.setTimer(100.msecs,
            { this.start(priv_nonce, peer_nonce); });
    }

    /***************************************************************************

        Constructor for loading existing channels from the DB.

        Params:
            chan_id = the channel ID to load from the DB.
            engine = the execution engine
            taskman = used to spawn tasks
            txPublisher = used to publish transactions to the Agora network.
            paymentRouter = used to forward HTLCs to the next hop
            onUpdateComplete = called when a channel update has completed
            db = the database to load the channel metadata from
            getFlashClient = delegate to get the FlashAPI client from

    ***************************************************************************/

    public this (in PublicKey key, Hash chan_id, FlashConfig flash_conf, Engine engine,
        ITaskManager taskman,
        void delegate (Transaction) txPublisher,
        PaymentRouter paymentRouter,
        OnChannelNotify onChannelNotify,
        OnPaymentComplete onPaymentComplete,
        OnUpdateComplete onUpdateComplete,
        FlashAPI delegate (in PublicKey peer_pk, Duration timeout) getFlashClient,
        ManagedDatabase db)
    {
        this.db = db;
        this.flash_conf = flash_conf;
        this.getFlashClient = getFlashClient;
        this.load(key, chan_id);

        this.engine = engine;
        this.taskman = taskman;
        this.txPublisher = txPublisher;
        this.update_signer = new UpdateSigner(this.flash_conf, this.conf,
            this.kp, this.peer_pk, this.engine, this.taskman, db);
        this.paymentRouter = paymentRouter;
        this.onChannelNotify = onChannelNotify;
        this.onPaymentComplete = onPaymentComplete;
        this.onUpdateComplete = onUpdateComplete;
        this.backoff = new Backoff(this.flash_conf.retry_multiplier,
            this.flash_conf.max_retry_delay.total!"msecs".to!uint);

        this.taskman.setTimer(100.msecs,
            (this.channel_updates.length == 0)
            ? { this.start(this.priv_nonce, this.peer_nonce); }  // funding not done yet
            : &this.eventLoop);  // funding already done
    }

    /***************************************************************************

        Load all known channels from the database and return it in a map.

        Params:
            flash_conf = the global flash configuration
            db = the DB to load from
            getFlashClient = delegate to get the FlashAPI client from
            engine = the execution engine
            taskman = used to spawn tasks
            txPublisher = used to publish transactions to the Agora network.
            paymentRouter = used to forward HTLCs to the next hop
            onUpdateComplete = called when a channel update has completed

        Returns:
            a map of any loaded channels

    ***************************************************************************/

    public static Channel[Hash][PublicKey] loadChannels (FlashConfig flash_conf,
        ManagedDatabase db,
        FlashAPI delegate (in PublicKey peer_pk, Duration timeout) getFlashClient,
        Engine engine, ITaskManager taskman,
        void delegate (Transaction) txPublisher, PaymentRouter paymentRouter,
        OnChannelNotify onChannelNotify,
        OnPaymentComplete onPaymentComplete,
        OnUpdateComplete onUpdateComplete )
    {
        Channel[Hash][PublicKey] channels;

        db.execute("CREATE TABLE IF NOT EXISTS channels " ~
            "(key BLOB NOT NULL, chan_id BLOB NOT NULL, data BLOB NOT NULL, " ~
            "update_signer BLOB, PRIMARY KEY (key, chan_id))");

        auto results = db.execute("SELECT key, chan_id FROM channels");
        foreach (ref row; results)
        {
            const key = deserializeFull!PublicKey(row.peek!(ubyte[])(0));
            const chan_id = deserializeFull!Hash(row.peek!(ubyte[])(1));
            channels[key][chan_id] = new Channel(key, chan_id, flash_conf, engine,
                taskman, txPublisher, paymentRouter, onChannelNotify,
                onPaymentComplete, onUpdateComplete, getFlashClient, db);
        }

        return channels;
    }

    /***************************************************************************

        Serialize and dump the channel metadata to the database.

    ***************************************************************************/

    public void dump () @trusted
    {
        this.serialize_buffer.length = 0;
        () @trusted { assumeSafeAppend(this.serialize_buffer); }();
        scope SerializeDg dg = (in ubyte[] data) @safe
        {
            this.serialize_buffer ~= data;
        };

        foreach (name; __traits(allMembers, meta))
        {
            auto field = __traits(getMember, meta, name);
            static if (isAssociativeArray!(typeof(field)))
                serializePart(serializeMap(field), dg);
            else
                serializePart(field, dg);
        }

        this.db.execute("REPLACE INTO channels (key, chan_id, data) VALUES (?, ?, ?)",
            this.kp.address.serializeFull, this.conf.chan_id.serializeFull,
            this.serialize_buffer);
    }

    /***************************************************************************

        Load the channel metadata for the given public key and channel ID from
        the database.

        Params:
            chan_id = the channel ID to load

    ***************************************************************************/

    private void load (PublicKey key, Hash chan_id) @trusted
    {
        auto results = this.db.execute(
            "SELECT data FROM channels WHERE key = ? AND chan_id = ?",
            key.serializeFull, chan_id.serializeFull);
        if (results.empty)
            return;  // nothing to load

        ubyte[] data = results.oneValue!(ubyte[]);

        scope DeserializeDg dg = (size) @safe
        {
            if (size > data.length)
                throw new Exception(
                    format("Requested %d bytes but only %d bytes available",
                        size, data.length));

            auto res = data[0 .. size];
            data = data[size .. $];
            return res;
        };

        foreach (name; __traits(allMembers, this.meta))
        {
            alias Type = typeof(__traits(getMember, this.meta, name));
            auto field = &__traits(getMember, this.meta, name);
            static if (isAssociativeArray!Type)
                *field = deserializeFull!(SerializeMap!Type)(dg)._map;
            else static if (is(Type == KeyPair))
            {
                // key-pair embeds const but compiler doesn't recognize
                // this as initialization rather than assignment
                auto val = deserializeFull!Type(dg);
                *cast(PublicKey*)&field.address = val.address;
                *cast(SecretKey*)&field.secret = val.secret;
            }
            else
                *field = deserializeFull!Type(dg);
        }
    }

    /***************************************************************************

        Returns:
            true if the channel is funded and is open

    ***************************************************************************/

    public bool isOpen ()
    {
        return this.state == ChannelState.Open;
    }

    /***************************************************************************

        Returns:
            true if the channel is currently in the process of collecting
            a signature. During that time new balance updates will not be
            accepted.

    ***************************************************************************/

    public bool isCollectingSignatures ()
    {
        return this.update_signer.isCollectingSignatures();
    }

    /***************************************************************************

        Returns:
            the current state of the channel

    ***************************************************************************/

    public ChannelState getState () @safe
    {
        return this.state;
    }

    /***************************************************************************

        Returns:
            our balance in the channel (HTLCs excluded as they're locked)

    ***************************************************************************/

    public Amount getOurBalance ()
    {
        return this.is_owner
            ? this.cur_balance.refund_amount
            : this.cur_balance.payment_amount;
    }

    /***************************************************************************

        Returns:
            the balance available for the provided payment direction
            (HTLCs excluded as they're locked)

    ***************************************************************************/

    public Amount getBalance (in PaymentDirection direction) @safe
    {
        // to pay towards owner, there must be enough peer balance (payment),
        // for the other direction the owner balance (refund) amount is checked.
        return direction == PaymentDirection.TowardsOwner
            ? this.cur_balance.payment_amount
            : this.cur_balance.refund_amount;
    }

    /***************************************************************************

        Called to check if this channel has any payment hashes for which
        the provided secrets hash to. If they do, a new update will be
        requested with the counter-party.

    ***************************************************************************/

    public void learnSecrets (in Hash[] secrets, in Hash[] revert_htlcs,
        in Height height) @safe
    {
        log.info("{}: learnSecrets({}, hashes: {}, known: {}, drop: {} height: {})",
            this.kp.address.flashPrettify,
            secrets.map!(s => s.flashPrettify),
            secrets.map!(s => s.hashFull.flashPrettify),
            this.payment_hashes.byKey.map!(s => s.flashPrettify),
            revert_htlcs.map!(s => s.flashPrettify),
            height);

        if (this.height < height)
            this.height = height;

        Hash[] matching_secrets, matching_rev_htlcs;
        foreach (secret; secrets)
            if (secret.hashFull() in this.payment_hashes)
                matching_secrets ~= secret;

        foreach (htlc; revert_htlcs)
            if (htlc in this.payment_hashes)
                matching_rev_htlcs ~= htlc;

        log.info("{}: learnSecrets matching: secrets: {} drop: {}",
            this.kp.address.flashPrettify,
            matching_secrets.map!(s => s.flashPrettify),
            matching_rev_htlcs.map!(s => s.flashPrettify));

        if (matching_secrets.length == 0 && matching_rev_htlcs.length == 0)
            return;

        this.secrets = matching_secrets;
        this.revert_htlcs = revert_htlcs.dup;
    }

    /***************************************************************************

        Start the setup stage of the channel. Should only be called once.

        A signing task will be spawned which attempts to collect the settlement
        and trigger transaction signatures from the counterparty. Additionally,
        the counter-party will request our own settlement & update signatures
        in the process.

        Once the signatures are collected and are validated on our side,
        the channel will be in `WaitingForFunding` state and will await for the
        funding transaction to be externalized before marking the channel
        as `Open`.

        Params:
            priv_nonce = the private nonce pair of this node for signing the
                initial settlement & trigger transactions
            peer_nonce = the public nonce pair which the counter-party will use
                to sign the initial settlement & trigger transactions

    ***************************************************************************/

    private void start (in PrivateNonce priv_nonce, in PublicNonce peer_nonce)
    {
        this.state = ChannelState.SettingUp;
        assert(this.cur_seq_id == 0);
        this.onChannelNotify(this.kp.address, this.conf.chan_id, this.state,
            ErrorCode.None);

        // initial output allocates all the funds back to the channel creator
        const seq_id = 0;
        Balance balance = { refund_amount : this.conf.capacity };
        Output[] outputs = this.buildBalanceOutputs(balance);

        const funding_utxo = UTXO(0,
            this.conf.funding_tx.outputs[this.conf.funding_utxo_idx]);
        const funding_utxo_hash = UTXO.getHash(
            hashFull(this.conf.funding_tx), this.conf.funding_utxo_idx);
        auto pair_res = this.update_signer.collectSignatures(this.peer, 0,
            outputs, priv_nonce, peer_nonce, funding_utxo_hash, funding_utxo);
        assert(pair_res.error == ErrorCode.None);  // todo: handle
        this.onSetupComplete(pair_res.value);

        // wait until the channel is open
        while (this.state != ChannelState.Open)
            this.taskman.wait(100.msecs);

        this.eventLoop();
    }

    /***************************************************************************

        Process incoming and outgoing requests with the calling fiber until
        the channel is closed.

    ***************************************************************************/

    private void eventLoop ()
    {
        if (this.getState == ChannelState.Closed)
            return;

        // Peer might not registered yet at the time we construct
        // the Channel, so we might need to re-try here in the event loop.
        if (this.peer is null)
        {
            this.peer = getFlashClient(this.peer_pk, this.flash_conf.timeout);

            // this would mean some of the metadata on disk is missing (flash registry)
            // FIXME: add retry mechanism for loading this channel until peer is found,
            // and force unilateral closure after a given timeout.
            if (this.peer is null)
                throw new Exception(format(
                    "Cannot find address of flash node in registry for the key %s",
                    this.peer_pk));
        }

        // check on start-up once in case this is a preloaded channel
        this.checkPublishSettlement();

LOuter: while (1)
        {
            scope (success)
                this.taskman.wait(100.msecs);

            if (!this.incoming_updates.empty)
            {
                this.handleIncomingUpdate(this.incoming_updates.front);
                this.incoming_updates.length = 0;
                assumeSafeAppend(this.incoming_updates);
            }

            if (this.state == ChannelState.Closed)
                break;

            if (!this.incoming_payments.empty)
            {
                this.handleIncomingPayment(this.incoming_payments.front);
                this.incoming_payments.length = 0;
                assumeSafeAppend(this.incoming_payments);
            }

            if (this.state == ChannelState.Closed)
                break;

            while (!this.outgoing_payments.empty)
            {
                if (this.handleOutgoingPayment(this.outgoing_payments.front))
                    this.outgoing_payments.popFront();
                else
                    continue LOuter;  // there are other requests in progress
            }

            if (this.state == ChannelState.Closed)
                break;

            // check if we can fold any HTLCs
            this.checkProposeUpdate();

            if (this.state == ChannelState.Closed)
                break;
        }
    }

    /***************************************************************************

        Called when the setup stage of the channel has been completed.

        If this node is the initial funder of the channel, the funding
        transaction will be signed and published to the blockchain.

        When the funding transaction is detected as being externalized,
        the channel state will be changed to `ChannelState.Open`.

        Params:
            update_pair = the signed initial settlement & trigger transactions.
                These will only be published to the blockchain in case of an
                un-cooperative or one-sided close of a channel.
                In the ideal case, the peers in the channel would agree to
                create a spend from the funding transaction and await until
                it's externalized to ensure the `update_pair` can no longer
                be accepted into the blockchain.

    ***************************************************************************/

    private void onSetupComplete (UpdatePair update_pair)
    {
        assert(this.state == ChannelState.SettingUp);

        // this is not technically an error, but it would be very strange
        // that a funding tx was published before signing was complete,
        // as the funding party carries the risk of having their funds locked.
        // in this case we skip straight to the open state.
        if (this.funding_tx_signed != Transaction.init)
            this.state = ChannelState.Open;
        else
            this.state = ChannelState.WaitingForFunding;

        // if we're the funder then it's time to publish the funding tx
        if (this.is_owner)
        {
            this.funding_tx_signed = this.conf.funding_tx.clone();
            this.funding_tx_signed.inputs[0].unlock
                = genKeyUnlock(this.kp.sign(this.conf.funding_tx));

            log.info("Publishing funding tx..");
            this.txPublisher(this.funding_tx_signed);
        }

        this.trigger_utxo = UTXO.getHash(update_pair.update_tx.hashFull(), 0);
        this.channel_updates ~= update_pair;
        this.known_settle_txs.put(update_pair.settle_tx.hashFull());

        if (this.state == ChannelState.Open)
        {
            this.dump();
            this.onChannelNotify(this.kp.address, this.conf.chan_id, this.state,
                ErrorCode.None);
        }
    }

    /***************************************************************************

        Called when the funding transaction of this channel has been
        externalized in the blockchain.

        The state of this channel will change to `Open`, which will make make
        the channel open to receiving new balance update requests - which it
        may accept or deny based on whether all the channel parties agree
        to the new balance update request.

        Params:
            tx = the funding transaction. Must be equal to the hash of the
                 funding transaction as set up in the initial `openChannel`
                 call - otherwise it's ignored.

    ***************************************************************************/

    private void onFundingTxExternalized (in Transaction tx)
    {
        this.funding_tx_signed = tx.clone();
        if (this.state == ChannelState.WaitingForFunding)
            this.state = ChannelState.Open;

        // todo: assert that this is really the actual balance
        // it shouldn't be technically possible that it mismatches
        Balance expected_balance = { refund_amount : this.conf.capacity };
        this.cur_balance = expected_balance;

        this.dump();
        this.onChannelNotify(this.kp.address, this.conf.chan_id, this.state,
            ErrorCode.None);
    }

    /***************************************************************************

        Called when the closing transaction of this channel has been
        externalized in the blockchain.

        The state of this channel will change to `Closed`, which means it may
        safely be destroyed by the owning node.

        Params:
            tx = the closing transaction. Must be equal to the hash of the
                 closing transaction as set up in the `closeChannel`
                 call - otherwise it's ignored.

    ***************************************************************************/

    private void onCloseTxExternalized (in Transaction tx)
    {
        log.info("{}: Received close tx: {}", this.kp.address.flashPrettify, tx.hashFull.flashPrettify);
        log.info("{}: Tx is: {}", this.kp.address.flashPrettify, tx);
        // todo: can notify Node that it can destroy this channel instance later
        this.state = ChannelState.Closed;
        this.onChannelNotify(this.kp.address, this.conf.chan_id, this.state,
            ErrorCode.None);
    }

    /***************************************************************************

        Called when the trigger / update transaction of this channel has been
        either detected in one of the nodes' transaction pools, or
        if it was externalized in the blockchain.

        This signals that the channel attemted to be unilaterally closed
        by some counter-party.

        The state of this channel will change to `PendingClose`, which will
        make it reject any new balance update requests.

        If the `tx` is not the latest update transaction the Channel will try
        to publish the latest update transaction. The Channel will then publish
        the latest matching settlement transaction.

        Params:
            tx = the trigger / update transaction.

    ***************************************************************************/

    public void onUpdateTxExternalized (in Transaction tx)
    {
        this.state = ChannelState.StartedUnilateralClose;
        this.onChannelNotify(this.kp.address, this.conf.chan_id, this.state,
            ErrorCode.None);

        // last update was published, publish the settlement
        if (tx == this.channel_updates[$ - 1].update_tx)
        {
            this.state = ChannelState.WaitingOnSettlement;
            this.onChannelNotify(this.kp.address, this.conf.chan_id, this.state,
                ErrorCode.None);
            this.update_ext_height = this.height;
        }
        else
        {
            // either the trigger or an outdated update tx was published.
            // publish the latest update first.
            const update_tx = this.channel_updates[$ - 1].update_tx;
            log.info("{}: Publishing latest update tx {}: {}",
                this.kp.address.flashPrettify, this.channel_updates.length, update_tx.hashFull().flashPrettify);
            this.txPublisher(cast()update_tx);
        }
    }

    /***************************************************************************

        If the state of the channel is `WaitingOnSettlement`, then check
        the current height and publish the Settlement transaction if the
        settlement timeout has expired on the Update transaction's Output.

    ***************************************************************************/

    private void checkPublishSettlement ()
    {
        if (this.state != ChannelState.WaitingOnSettlement)
            return;  // nothing to do

        // should have been set if state changed to WaitingOnSettlement
        assert(this.update_ext_height != Height(0));

        // ready to publish settlement
        if (this.height >= this.update_ext_height + this.conf.settle_time)
        {
            const settle_tx = this.channel_updates[$ - 1].settle_tx;
            log.info("{}: Publishing last settle tx {}: {}",
                this.kp.address.flashPrettify, this.channel_updates.length,
                settle_tx.hashFull().flashPrettify);
            this.txPublisher(cast()settle_tx);
        }
    }

    /***************************************************************************

        Called when a settlement transaction has been detected as externalized.
        This was a unilateral channel close.

        At this point the channel becomes closed and it is safe to destroy
        all of its associated data. If the counter-party was the initiator
        of the channel closure but did not attempt to collaborate on the close,
        or if the counter-party deliberately published an outdated settlement
        transaction, then the peer could be added to the local node's ban list.

        Note that it cannot be proven that a peer acted maliciously when
        publishing a stale update / settlement. Consider the following scenario:

        - Nodes A and B have settle & update transactions for seq 1.
        - They try to negotiate settle & update transactions for seq 2.
        - Node A receives settle & update for seq 2, but refuses to send back
          the update signature for seq 2 to Node B.
        - Node A stops collaborating for a long time, either deliberately or
          due to network issues.
        - Node B is forced to try to close the channel by publishing the trigger
          transaction and its latest update transaction with seq 1.
        - Node A comes back online, sees the trigger / update transactions
          published to the blockchain. It quickly publishes update with seq 2,
          and the associated settlement transaction.

        There was no loss of funds in the above case, but node B could appear
        to look like the bad actor to the external observers because it
        published a stale update transaction.

        In fact, neither node could necessarily be at fault. It's possible
        there was a network outage at Node A's side.

        At this time we're unaware of any algorithm that allows for an
        atomic swap of each others' secrets (signatures) to prevent having
        one party accept a signature but never returning its own signature back.

        Params:
            tx = the settlement transaction.

    ***************************************************************************/

    private void onSettleTxExternalized (in Transaction tx)
    {
        // todo: assert this is the actual settlement transaction
        this.state = ChannelState.Closed;
        this.onChannelNotify(this.kp.address, this.conf.chan_id, this.state,
            ErrorCode.None);
    }

    /***************************************************************************

        Called when the counter-party requests a settlement signature.
        If the sequence ID is unrecognized, it will return an error code.

        Params:
            seq_id = the sequence ID.

        Returns:
            the settlement signature,
            or an error code with an optional error message.

    ***************************************************************************/

    public Result!Signature onRequestSettleSig (in uint seq_id)
    {
        if (seq_id < this.channel_updates.length)
            return Result!Signature(this.channel_updates[seq_id].our_settle_sig);

        const cur_seq_id = this.update_signer.getSeqID();
        if (seq_id != cur_seq_id)
            return Result!Signature(ErrorCode.InvalidSequenceID,
                format("onRequestSettleSig: expected seq_id: %s. Got: %s",
                    cur_seq_id, seq_id));

        return this.update_signer.getSettleSig();
    }

    /***************************************************************************

        Called when the counter-party requests an update signature.
        If the sequence ID is unrecognized, it will return an error code.

        Params:
            seq_id = the sequence ID.

        Returns:
            the update signature,
            or an error code with an optional error message.

    ***************************************************************************/

    public Result!Signature onRequestUpdateSig (in uint seq_id)
    {
        if (seq_id < this.channel_updates.length)
            return Result!Signature(this.channel_updates[seq_id].our_update_sig);

        const cur_seq_id = this.update_signer.getSeqID();
        if (seq_id != cur_seq_id)
            return Result!Signature(ErrorCode.InvalidSequenceID,
                format("onRequestUpdateSig: expected seq_id: %s. Got: %s",
                    cur_seq_id, seq_id));

        return this.update_signer.getUpdateSig();
    }

    public Result!bool onConfirmedChannelUpdate (in uint seq_id)
    {
        const cur_seq_id = this.update_signer.getSeqID();
        if (seq_id != cur_seq_id)
            Result!bool(ErrorCode.InvalidSequenceID,
                format("onConfirmedChannelUpdate: expected seq_id: %s. Got: %s",
                    cur_seq_id, seq_id));

        this.update_signer.onConfirmedChannelUpdate();
        return Result!bool(true);
    }

    /***************************************************************************

        Check whether we should propose a new update, and if so propose it
        with the counter-party.

        This folds any outgoing HTLCs for which we've either learned a secret
        for, or for which the HTLCs height locks have expired.

    ***************************************************************************/

    private void checkProposeUpdate ()
    {
        auto secrets = this.secrets;
        auto revert_htlcs = this.revert_htlcs;

        Height update_height = this.height;
        auto new_balance = this.foldHTLCs(this.cur_balance, this.secrets,
            this.revert_htlcs, update_height);
        auto new_outputs = this.buildBalanceOutputs(new_balance);
        if (new_balance == cur_balance)
            return;  // nothing to propose yet

        this.outbound_in_progress = true;
        scope (exit) this.outbound_in_progress = false;

        uint new_seq_id = this.cur_seq_id + 1;
        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();

        Result!PublicNonce result = Result!PublicNonce(ErrorCode.Unknown);
        const fail_time = Clock.currTime() + this.flash_conf.max_retry_time;
        foreach (attempt; 0 .. uint.max)
        {
            const WaitTime = this.backoff.getDelay(attempt).msecs;
            if (Clock.currTime() + WaitTime >= fail_time)
                break;  // timeout

            this.taskman.wait(WaitTime);

            // re-fold
            if (update_height != this.height)
            {
                secrets = this.secrets;
                revert_htlcs = this.revert_htlcs;
                update_height = this.height;
                new_balance = this.foldHTLCs(this.cur_balance, this.secrets,
                    this.revert_htlcs, update_height);
                new_outputs = this.buildBalanceOutputs(new_balance);
            }

            // todo: there may be a double call here if the first request timed-out
            // and the client sends this request again.
            result = this.peer.proposeUpdate(this.kp.address,
                PublicKey(this.peer_pk), this.conf.chan_id, new_seq_id,
                cast(Hash[])this.secrets,
                cast(Hash[])this.revert_htlcs, pub_nonce, update_height);

            if (result.error)
            {
                // peer has priority
                if (result.error == ErrorCode.ProposalInProgress)
                    return;

                log.info("{}: Error proposing update with {}: {}",
                    this.kp.address.flashPrettify, this.peer_pk.flashPrettify, result);
                continue;
            }

            break;
        }

        if (result.error)
            return; // TODO: is further error recovery needed?

        const old_balance = this.cur_balance;
        this.cur_seq_id = new_seq_id;
        const peer_nonce = result.value;

        assert(this.channel_updates[0].update_tx.outputs.length == 1);
        const update_utxo = UTXO(0,
            this.channel_updates[0].update_tx.outputs[0]);
        const update_utxo_hash = UTXO.getHash(
            hashFull(this.channel_updates[0].update_tx),0);
        auto update_pair_res = this.update_signer.collectSignatures(this.peer,
            new_seq_id, new_outputs, priv_nonce, peer_nonce,
            update_utxo_hash, update_utxo);  // spend from trigger tx
        assert(update_pair_res.error == ErrorCode.None); // todo: handle
        auto update_pair = update_pair_res.value;
        this.known_settle_txs.put(update_pair.settle_tx.hashFull());

        log.info("{}: +Update+ Got new pair from {}! Balanced updated: {}",
            this.kp.address.flashPrettify, this.peer_pk.flashPrettify, new_balance);
        this.channel_updates ~= update_pair;
        this.cur_balance = new_balance;

        // Filter out the htlcs that are not pending on this channel
        auto rev_htlcs_filtered = revert_htlcs.filter!(payment_hash =>
            payment_hash in this.payment_hashes).array;

        // Save dropped htlcs
        foreach (payment_hash; rev_htlcs_filtered)
            this.dropped_htlcs[payment_hash] = this.payment_hashes[payment_hash];
        foreach (secret; secrets)
            this.payment_hashes.remove(secret.hashFull());
        rev_htlcs_filtered.each!(hash => this.payment_hashes.remove(hash));

        this.onUpdateComplete(this.kp.address, secrets, rev_htlcs_filtered);
        this.dump();
    }

    /***************************************************************************

        Called by a counter-party when it wants to fold HTLCs by revealing
        secrets or when forced to spend HTLCs for which the time locks have
        expired.

        Schedules this request for later.

        Params:
            seq_id = the new sequence ID
            secrets = any new secrets
            peer_nonce = the public nonce the counter-party will use
            height = the latest known height for the counter-party. If we don't
                agree with this height we will reject the update request.

        Returns:
            our nonce to use in the signing process, or an error code

    ***************************************************************************/

    public Result!PublicNonce onProposedUpdate (in uint seq_id,
        in Hash[] secrets, in Hash[] revert_htlcs, in PublicNonce peer_nonce,
        in Height height) @trusted
    {
        if (!this.isOpen())
            return Result!PublicNonce(ErrorCode.ChannelNotOpen,
                "This channel is not open");

        if (this.isCollectingSignatures())
            return Result!PublicNonce(ErrorCode.SigningInProcess,
                "This channel is still collecting signatures for a "
                ~ "previous sequence ID");

        // we already have an outbound request and we're the leader for this round
        if (this.outbound_in_progress)
            return Result!PublicNonce(ErrorCode.ProposalInProgress);

        // calling node proposed update & payment at the same time,
        // something's wrong with that node
        if (!this.incoming_payments.empty)
            return Result!PublicNonce(ErrorCode.ProposalInProgress);

        // we force new sequences to be exactly the next in sequence to avoid
        // running out of sequence IDs
        if (seq_id != this.cur_seq_id + 1)
            return Result!PublicNonce(ErrorCode.InvalidSequenceID,
                format("onProposedUpdate: expected seq_id: %s. Got: %s",
                    this.cur_seq_id + 1, seq_id));

        // Filter out the htlcs that are not pending on this channel
        auto rev_htlcs_filtered = revert_htlcs.filter!(payment_hash =>
            payment_hash in this.payment_hashes).array;

        const old_balance = this.cur_balance;
        auto new_balance = this.foldHTLCs(old_balance, secrets, rev_htlcs_filtered,
            height);

        if (new_balance == cur_balance)
            return Result!PublicNonce(ErrorCode.UpdateRejected,
                "Proposed balance is the same as current one");

        log.info("{}: onProposedUpdate from {} accepted ({}, {}, {}, {})",
            this.kp.address.flashPrettify, this.peer_pk.flashPrettify,
            seq_id, secrets.map!(s => s.flashPrettify),
            revert_htlcs.map!(s => s.flashPrettify), height);

        auto new_outputs = this.buildBalanceOutputs(new_balance);

        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();

        log.info("{}: Before folding: {}. After folding: {}", this.kp.address.flashPrettify,
            old_balance, new_balance);

        // let the work fiber handle it next
        this.incoming_updates ~= IncomingUpdate(seq_id, new_outputs,
            new_balance, priv_nonce, peer_nonce, secrets, rev_htlcs_filtered);

        return Result!PublicNonce(pub_nonce);
    }

    /***************************************************************************

        Start the signing process for an incoming payment.

        Params:
            payment = the incoming payment to sign

    ***************************************************************************/

    private void handleIncomingPayment (IncomingPayment payment)
    {
        const direction = this.is_owner ?
            PaymentDirection.TowardsOwner : PaymentDirection.TowardsPeer;
        auto new_balance = this.buildUpdatedBalance(direction,
            this.cur_balance, payment.amount, payment.payment_hash,
            payment.lock_height, payment.height);
        auto new_outputs = this.buildBalanceOutputs(new_balance);

        log.info("{}: Handling incoming payment balance request: {}",
            this.kp.address.flashPrettify, new_balance);

        this.cur_seq_id = payment.seq_id;

        assert(this.channel_updates[0].update_tx.outputs.length == 1);
        const update_utxo = UTXO(0,
            this.channel_updates[0].update_tx.outputs[0]);
        const update_utxo_hash = UTXO.getHash(
            hashFull(this.channel_updates[0].update_tx),0);

        auto update_pair_res = this.update_signer.collectSignatures(this.peer,
            payment.seq_id, new_outputs, payment.priv_nonce, payment.peer_nonce,
            update_utxo_hash, update_utxo);  // spend from trigger tx

        if (update_pair_res.error)
        {
            log.error("Couldn't sign incoming payment: {}. Error: {}",
                payment, update_pair_res.message);
            return;  // todo: anything else we can do here?
        }

        auto update_pair = update_pair_res.value;
        this.known_settle_txs.put(update_pair.settle_tx.hashFull());

        log.info("{}: Got new pair from {}! Balance updated! {}",
            this.kp.address.flashPrettify, this.peer_pk.flashPrettify, new_balance);
        this.channel_updates ~= update_pair;
        this.cur_balance = new_balance;

        // prepare for secrets
        this.payment_hashes[payment.payment_hash] = payment.shared_secret;

        // route to the next node
        if (payment.payload.next_chan_id != Hash.init)
        {
            OnionPacket next_packet = nextPacket(payment.packet);

            log.info("{}: Routing to next channel: {}", this.kp.address.flashPrettify,
                payment.payload.next_chan_id.flashPrettify);
            this.paymentRouter(this.kp.address, payment.payload.next_chan_id,
                payment.payment_hash,
                payment.payload.forward_amount,
                Height(payment.lock_height - this.last_update.htlc_delta),
                next_packet);
        }
        else
            // propose an update afterwards
            this.onPaymentComplete(this.kp.address, this.conf.chan_id,
                payment.payment_hash);

        this.dump();
    }

    /***************************************************************************

        Start the signing process for an outgoing payment.

        Params:
            payment = the outgoing payment to sign

    ***************************************************************************/

    private bool handleOutgoingPayment (in OutgoingPayment payment)
    {
        const direction = this.is_owner ?
            PaymentDirection.TowardsPeer : PaymentDirection.TowardsOwner;
        const cur_amount = this.getBalance(direction);
        if (cur_amount < payment.amount)
        {
            this.onPaymentComplete(this.kp.address, this.conf.chan_id,
                payment.payment_hash, ErrorCode.ExceedsMaximumPayment);
            return true;  // remove it from the queue
        }

        this.outbound_in_progress = true;
        scope (exit) this.outbound_in_progress = false;

        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();
        const new_seq_id = this.cur_seq_id + 1;

        Result!PublicNonce result = Result!PublicNonce(ErrorCode.Unknown);
        const fail_time = Clock.currTime() + this.flash_conf.max_retry_time;
        foreach (attempt; 0 .. uint.max)
        {
            const WaitTime = this.backoff.getDelay(attempt).msecs;
            if (Clock.currTime() + WaitTime >= fail_time)
                break;  // timeout
            this.taskman.wait(WaitTime);

            result = this.peer.proposePayment(this.kp.address,
                PublicKey(this.peer_pk),
                this.conf.chan_id, new_seq_id,
                payment.payment_hash, payment.amount, payment.lock_height,
                payment.packet, pub_nonce, payment.height);

            if (result.error)
            {
                // peer has priority
                if (result.error == ErrorCode.ProposalInProgress)
                    return false;

                log.info("{}: Error proposing payment: {}", this.kp.address.flashPrettify,
                    result);

                continue;
            }

            break;
        }

        if (result.error)
        {
            log.error("Couldn't propose outgoing payment: {}. Error: {}",
                payment, result.message);
            this.onPaymentComplete(this.kp.address, this.conf.chan_id,
                payment.payment_hash, result.error);
            return true;  // remove it from the queue
        }

        const peer_nonce = result.value;
        auto new_balance = this.buildUpdatedBalance(direction,
            this.cur_balance, payment.amount, payment.payment_hash,
            payment.lock_height, payment.height);
        auto new_outputs = this.buildBalanceOutputs(new_balance);

        log.info("{}: Created outgoing payment balance request: {}",
            this.kp.address.flashPrettify, new_balance);

        assert(this.channel_updates[0].update_tx.outputs.length == 1);
        const update_utxo = UTXO(0,
            this.channel_updates[0].update_tx.outputs[0]);
        const update_utxo_hash = UTXO.getHash(
            hashFull(this.channel_updates[0].update_tx),0);

        auto update_pair_res = this.update_signer.collectSignatures(this.peer,
            new_seq_id, new_outputs, priv_nonce, peer_nonce,
            update_utxo_hash, update_utxo);  // spend from trigger tx

        if (update_pair_res.error)
        {
            log.error("Couldn't sign outgoing payment: {}. Error: {}",
                payment, update_pair_res.message);
            this.onPaymentComplete(this.kp.address, this.conf.chan_id,
                payment.payment_hash, update_pair_res.error);
            return true;  // remove it from the queue
        }

        this.cur_seq_id = new_seq_id;
        auto update_pair = update_pair_res.value;
        this.known_settle_txs.put(update_pair.settle_tx.hashFull());

        log.info("{}: Got new pair from {}! Balanced updated. New balance: {}",
            this.kp.address.flashPrettify, this.peer_pk.flashPrettify, new_balance);
        this.channel_updates ~= update_pair;
        this.cur_balance = new_balance;

        if (payment.payment_hash !in this.payment_hashes)
            this.payment_hashes[payment.payment_hash] = Point.init;
        return true;
    }

    /***************************************************************************

        Start the signing process for an incoming update.

        Params:
            update = the incoming update to sign

    ***************************************************************************/

    private void handleIncomingUpdate (IncomingUpdate update)
    {
        const old_balance = this.cur_balance;

        assert(this.channel_updates[0].update_tx.outputs.length == 1);
        const update_utxo = UTXO(0,
            this.channel_updates[0].update_tx.outputs[0]);
        const update_utxo_hash = UTXO.getHash(
            hashFull(this.channel_updates[0].update_tx),0);

        auto update_pair_res = this.update_signer.collectSignatures(this.peer,
            update.seq_id,
            update.outputs, update.priv_nonce,
            update.peer_nonce,
            update_utxo_hash, update_utxo);  // spend from trigger tx

        if (update_pair_res.error != ErrorCode.None)
        {
            log.error("Couldn't sign incoming update: {}. Error: {}",
                update, update_pair_res.message);
            return;
        }

        this.cur_seq_id = update.seq_id;
        auto update_pair = update_pair_res.value;
        this.known_settle_txs.put(update_pair.settle_tx.hashFull());

        log.info("{}: Got new pair from {}! Balance updated: {}",
            this.kp.address.flashPrettify, this.peer_pk.flashPrettify, update.balance);
        this.channel_updates ~= update_pair;
        this.cur_balance = update.balance;

        // Filter out the htlcs that are not pending on this channel
        auto rev_htlcs_filtered = update.revert_htlcs.filter!(payment_hash =>
            payment_hash in this.payment_hashes).array;

        // Save dropped htlcs
        foreach (payment_hash; rev_htlcs_filtered)
            this.dropped_htlcs[payment_hash] = this.payment_hashes[payment_hash];
        foreach (secret; update.secrets)
            this.payment_hashes.remove(secret.hashFull());
        rev_htlcs_filtered.each!(hash => this.payment_hashes.remove(hash));

        this.onUpdateComplete(this.kp.address, update.secrets,
            update.revert_htlcs);
    }

    /***************************************************************************

        Queue a payment to be routed through this channel.
        This could be for our own payment, or forwarded from another node.

        Params:
            payment_hash = the invoice payment hash
            amount = the invoice amount
            lock_height = the lock height for the outgoing HTLC
            packet = the packet which contains the encrypted payload for the
                counter-party.

    ***************************************************************************/

    public void queueNewPayment (in Hash payment_hash, in Amount amount,
        in Height lock_height, in OnionPacket packet, in Height height) @safe
    {
        log.info("{}: Queued new payment: {}", this.kp.address.flashPrettify,
            payment_hash.flashPrettify);

        this.outgoing_payments ~= OutgoingPayment(payment_hash, amount,
            lock_height, packet, height);
    }

    /***************************************************************************

        Called by a counter-party node when it wants to propose a new payment.

        Schedules the payment to be handled later.

        Params:
            seq_id = the new sequence ID
            payment_hash = the invoice payment hash
            amount = the amount the counter-party wants to forward
            lock_height = the lock height for the outgoing HTLC
            payload = the decrypted payload
            peer_nonce = the public nonce the counter-party will use for signing
            height = the current known block height
            shared_secret = secret used to decrypt the payload

        Returns:
            the public nonce this node will use, or an error

    ***************************************************************************/

    public Result!PublicNonce onProposedPayment (in uint seq_id,
        in Hash payment_hash, in Amount amount, in Height lock_height,
        in OnionPacket packet, in Payload payload, in PublicNonce peer_nonce,
        in Height height, in Point shared_secret) @trusted
    {
        if (!this.isOpen())
            return Result!PublicNonce(ErrorCode.ChannelNotOpen,
                "This channel is not open");

        if (this.isCollectingSignatures())
            return Result!PublicNonce(ErrorCode.SigningInProcess,
                "This channel is still collecting signatures for a "
                ~ "previous sequence ID");

        if (this.outbound_in_progress)
            return Result!PublicNonce(ErrorCode.ProposalInProgress);

        // calling node proposed update & payment at the same time,
        // something's wrong with that node
        if (!this.incoming_updates.empty)
            return Result!PublicNonce(ErrorCode.ProposalInProgress);

        // Forwarding HTLC. Check balance first.
        // todo: check the owner balance first
        // todo: need to find the next channel ID (if forwarding packet),
        // and check our balance.
        const direction = this.is_owner ?
            PaymentDirection.TowardsOwner : PaymentDirection.TowardsPeer;
        const cur_amount = this.getBalance(direction);
        if (cur_amount < amount)
            return Result!PublicNonce(ErrorCode.ExceedsMaximumPayment,
                format("Insufficient funds to route this payment. "
                    ~ "Amount requested: %s. Available: %s. Balance: %s",
                    amount, cur_amount, this.cur_balance));

        // todo: also check fees here
        if (amount < payload.forward_amount /* + this.conf.payment_fee */)
            return Result!PublicNonce(ErrorCode.AmountTooSmall,
                format("Amount being forwarded is too small. Amount: %s. Forward amount: %s",
                    amount, payload.forward_amount));

        // incoming lock height must be greater than outgoing lock height
        // todo: also take into account the desired delta
        if (payload.next_chan_id != Hash.init
            && lock_height <= height + this.last_update.htlc_delta)
            return Result!PublicNonce(ErrorCode.LockTooLarge,
                format("Lock height is too low. Required delta: %s",
                    this.last_update.htlc_delta));

        // todo
        version (none)
        if (amount > this.conf.max_payment_amount)
            return Result!PublicNonce(ErrorCode.ExceedsMaximumPayment,
                "Exceeds maximum payment the node is comfortable routing");

        // we force new sequences to be exactly the next in sequence to avoid
        // running out of sequence IDs
        if (seq_id != this.cur_seq_id + 1)
            return Result!PublicNonce(ErrorCode.InvalidSequenceID,
                format("onProposedPayment: expected seq_id: %s. Got: %s",
                    this.cur_seq_id + 1, seq_id));

        log.info("{}: onProposedPayment from {} accepted ({}, {}, {}, {}, {})",
            this.kp.address.flashPrettify, this.peer_pk.flashPrettify,
            this.conf.chan_id, seq_id, payment_hash.flashPrettify, amount,
            lock_height);

        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();

        // let the work fiber handle it next
        this.incoming_payments ~= IncomingPayment(seq_id, priv_nonce,
            peer_nonce, packet, payload, payment_hash, amount, height,
            lock_height, shared_secret);

        return Result!PublicNonce(pub_nonce);
    }

    /***************************************************************************

        Fold HTLCs for which we've learned the secrets for or which have
        their lock time expired.

        TODO: can we merge this and buildUpdatedBalance() ?

        Params:
            old_balance = the current balance
            secrets = any new secrets we've discovered
            height = the current known block height

        Returns:
            the new balance to use during the next signing process

    ***************************************************************************/

    public Balance foldHTLCs (in Balance old_balance, in Hash[] secrets,
        in Hash[] revert_htlcs, in Height height)
    {
        Balance new_balance;
        new_balance.refund_amount = old_balance.refund_amount;
        new_balance.payment_amount = old_balance.payment_amount;

        // assocArray doesn't work with const..
        version (none)
            Hash[Hash] payment_hashes = secrets
                .map!(s => tuple(s.hashFull, s))
                .assocArray;

        Hash[Hash] payment_hashes;
        foreach (secret; secrets)
            payment_hashes[secret.hashFull()] = secret;

        // fold outgoing HTLCs
        foreach (payment_hash, htlc; old_balance.outgoing_htlcs)
        {
            if (htlc.lock_height < height || revert_htlcs.canFind(payment_hash))
            {
                log.info("{}: Fold: Folded outgoing time-expired/dropped HTLC: {}", this.kp.address.flashPrettify, payment_hash);
                if (!new_balance.refund_amount.add(htlc.amount))
                    assert(0);
            }
            else if (payment_hash in payment_hashes)  // fold secret HTLC
            {
                log.info("{}: Fold: Folded outgoing secret-revealed HTLC: {}", this.kp.address.flashPrettify, payment_hash.flashPrettify);
                if (!new_balance.payment_amount.add(htlc.amount))
                    assert(0);
            }
            else
            {
                //log.info("{}: Fold: Did not fold outgoing HTLC: {}", this.kp.address.flashPrettify, payment_hash.flashPrettify);
                new_balance.outgoing_htlcs[payment_hash] = htlc;
            }
        }

        // fold incoming HTLCs
        foreach (payment_hash, htlc; old_balance.incoming_htlcs)
        {
            if (htlc.lock_height < height || revert_htlcs.canFind(payment_hash))
            {
                log.info("{}: Fold: Folded incoming time-expired/dropped HTLC: {}", this.kp.address.flashPrettify, payment_hash);
                if (!new_balance.payment_amount.add(htlc.amount))
                    assert(0);
            }
            else if (payment_hash in payment_hashes)  // fold secret HTLC
            {
                log.info("{}: Fold: Folded incoming secret-revealed HTLC: {}", this.kp.address.flashPrettify, payment_hash.flashPrettify);
                if (!new_balance.refund_amount.add(htlc.amount))
                    assert(0);
            }
            else
            {
                //log.info("{}: Fold: Did not fold outgoing HTLC: {}", this.kp.address.flashPrettify, payment_hash.flashPrettify);
                new_balance.incoming_htlcs[payment_hash] = htlc;
            }
        }

        return new_balance;
    }

    /***************************************************************************

        Add a new HTLC to the balance and fold any HTLCs for which the
        timeout has expired.

        Params:
            old_balance = the current balance
            amount = the invoice amount
            payment_hash = the invoice payment hash
            lock_height = the lock height for the outgoing HTLC
            height = the current known block height

        Returns:
            the new balance to use during the next signing process

    ***************************************************************************/

    public Balance buildUpdatedBalance (in PaymentDirection direction,
        in Balance old_balance, in Amount amount, in Hash payment_hash,
        in Height lock_height, in Height height)
    {
        Balance new_balance;
        new_balance.refund_amount = old_balance.refund_amount;
        new_balance.payment_amount = old_balance.payment_amount;

        // deep-dup
        foreach (hash, htlc; old_balance.outgoing_htlcs)
        {
            // fold expired HTLCs
            if (htlc.lock_height < height)
            {
                log.info("{}: Fold: Folded outgoing HTLC: {}", this.kp.address.flashPrettify, payment_hash);
                if (!new_balance.refund_amount.add(htlc.amount))
                    assert(0);
            }
            else
            {
                log.info("{}: Fold: Not folded outgoing HTLC: {}", this.kp.address.flashPrettify, payment_hash);
                new_balance.outgoing_htlcs[payment_hash] = htlc;
            }
        }

        // ditto (todo: avoid copy-paste)
        foreach (hash, htlc; old_balance.incoming_htlcs)
        {
            // fold expired HTLCs
            if (htlc.lock_height < height)
            {
                log.info("{}: Fold: Folded incoming HTLC: {}", this.kp.address.flashPrettify, payment_hash);
                if (!new_balance.payment_amount.add(htlc.amount))
                    assert(0);
            }
            else
            {
                log.info("{}: Fold: Not folded incoming HTLC: {}", this.kp.address.flashPrettify, payment_hash);
                new_balance.incoming_htlcs[payment_hash] = htlc;
            }
        }

        if (direction == PaymentDirection.TowardsPeer)
        {
            // add new HTLC
            if (!new_balance.refund_amount.sub(amount))
                assert(0);
            new_balance.outgoing_htlcs[payment_hash] = HTLC(lock_height, amount);
        }
        else if (direction == PaymentDirection.TowardsOwner)
        {
            // add new HTLC
            if (!new_balance.payment_amount.sub(amount))
                assert(0);
            new_balance.incoming_htlcs[payment_hash] = HTLC(lock_height, amount);
        }
        else assert(0);

        return new_balance;
    }

    /***************************************************************************

        Called when a new block has been externalized.

        Checks if the block contains funding / trigger / update / settlement
        transactions which belong to this channel, and calls one of the
        handler routines based on the detected transaction type.

        Params:
            block = an externalized block

    ***************************************************************************/

    public void onBlockExternalized (in Block block) @trusted
    {
        this.height = block.header.height;

        foreach (tx; block.txs)
        {
            if (tx.hashFull() == this.conf.funding_tx_hash)
            {
                log.info("{}: Funding tx externalized({})",
                    this.kp.address.flashPrettify, tx.hashFull().flashPrettify);
                this.onFundingTxExternalized(tx);
            }
            else
            if (this.isClosingTx(tx))
            {
                log.info("{}: Close tx externalized({})",
                    this.kp.address.flashPrettify, tx.hashFull().flashPrettify);
                this.onCloseTxExternalized(tx);
            }
            else
            if (this.isUpdateTx(tx))
            {
                log.info("{}: Update tx externalized({})",
                    this.kp.address.flashPrettify, tx.hashFull().flashPrettify);
                this.onUpdateTxExternalized(tx);
            }
            else
            if (this.isSettleTx(tx))
            {
                log.info("{}: Settle tx externalized({})",
                    this.kp.address.flashPrettify, tx.hashFull().flashPrettify);
                this.onSettleTxExternalized(tx);
            }
        }

        this.checkPublishSettlement();
    }

    /***************************************************************************

        Checks if this is a closing transaction belonging to this channel.

        Params:
            tx = the transaction to check.

        Returns:
            true if this is the matching closing transaction.

    ***************************************************************************/

    private bool isClosingTx (in Transaction tx)
    {
        return tx == this.pending_close.tx;
    }

    /***************************************************************************

        Checks if this is a trigger or update transaction belonging to
        this channel.

        Params:
            tx = the transaction to check.

        Returns:
            true if this is one of the trigger / update transactions.

    ***************************************************************************/

    private bool isUpdateTx (in Transaction tx)
    {
        if (tx.inputs.length != 1)
            return false;

        // todo: this is also the close tx, check its utxo first
        if (tx.inputs[0].utxo == UTXO.getHash(
            hashFull(this.conf.funding_tx), this.conf.funding_utxo_idx))
            return true;

        // todo: could there be a timing issue here if our `channel_updates`
        // are not updated fast enough? chances are very slim, need to verify.
        // todo: optimize by caching trigger tx utxo
        return this.channel_updates.length > 0
            && tx.inputs[0].utxo == this.trigger_utxo;
    }

    /***************************************************************************

        Checks if this is one of the settlement transactions belonging to
        this channel.

        Params:
            tx = the transaction to check.

        Returns:
            true if this is one of the matching settlement transactions.

    ***************************************************************************/

    private bool isSettleTx (in Transaction tx)
    {
        return !!(hashFull(tx) in this.known_settle_txs);
    }

    /***************************************************************************

        Begin a collaborative close of the channel.

        The node will send the counter-party a `closeChannel` request,
        with the sequence ID of the last known state.

        The counter-party should return its signature for the closing
        transaction.

        Params:
            fee = amount of fees to include in closing TX

    ***************************************************************************/

    public Result!bool beginCollaborativeClose (Amount fee) @trusted
    {
        if (this.state != ChannelState.Open &&
            this.state != ChannelState.RejectedCollaborativeClose)
            return Result!bool(ErrorCode.ChannelNotOpen,
                "Channel is not open");

        this.state = ChannelState.StartedCollaborativeClose;
        this.onChannelNotify(this.kp.address, this.conf.chan_id, this.state,
            ErrorCode.None);

        this.taskman.setTimer(100.msecs,
        {
            Pair priv_nonce = Pair.random();
            const fail_time = Clock.currTime() + this.flash_conf.max_retry_time;
            Result!Point close_res = Result!Point(ErrorCode.Unknown);

            foreach (attempt; 0 .. uint.max)
            {
                const WaitTime = this.backoff.getDelay(attempt).msecs;
                if (Clock.currTime() + WaitTime >= fail_time)
                {
                    // timeout
                    this.state = ChannelState.RejectedCollaborativeClose;
                    this.onChannelNotify(this.kp.address, this.conf.chan_id,
                        this.state, close_res.error);
                    return;
                }

                this.taskman.wait(WaitTime);

                close_res = this.peer.closeChannel(this.kp.address,
                    PublicKey(this.peer_pk), this.conf.chan_id, this.cur_seq_id,
                    priv_nonce.V, fee);
                if (close_res.error)
                {
                    // todo: retry with bigger fee if smaller fee was rejected?
                    log.info("{}: closeChannel() request rejected: {}",
                        this.kp.address.flashPrettify, close_res);
                    continue;
                }

                break;
            }

            this.collectCloseSignatures(priv_nonce, close_res.value, fee);
        });

        return Result!bool(true);
    }

    /***************************************************************************

        Begin a collaborative close of the channel.

        The node will send the counter-party a `closeChannel` request,
        with the sequence ID of the last known state.

        The counter-party should return its signature for the closing
        transaction.

    ***************************************************************************/

    public Result!bool beginUnilateralClose () @trusted
    {
        if (this.state != ChannelState.Open &&
            this.state != ChannelState.RejectedCollaborativeClose)
            return Result!bool(ErrorCode.ChannelNotOpen, "Channel is not open");

        this.state = ChannelState.StartedUnilateralClose;
        this.onChannelNotify(this.kp.address, this.conf.chan_id, this.state,
            ErrorCode.None);

        this.taskman.setTimer(100.msecs,
        {
            // publish trigger tx. onUpdateTxExternalized() will handle the rest.
            auto trigger_tx = this.channel_updates[0].update_tx;
            log.info("{}: Publishing trigger tx: {}",
                this.kp.address.flashPrettify,
                trigger_tx.hashFull().flashPrettify);
            this.txPublisher(trigger_tx);
        });

        return Result!bool(true);
    }

    /***************************************************************************

        Generate the Outputs for the refund / payment and any HTLCs in the
        balance.

        Params:
            balance = the balance to convert
            fee = fees to deduct from the outputs

        Returns:
            an Output array, to be used in the settle / close transactions

    ***************************************************************************/

    private Output[] buildBalanceOutputs (Balance balance, Amount fee = 0.coins)
    {
        Output[] outputs;

        // Deduct the fees from payment amount as much as possible
        if (balance.payment_amount >= fee)
        {
            if (!balance.payment_amount.sub(fee))
                assert(0);
        }
        else
        {
            if (!fee.sub(balance.payment_amount)  || !balance.refund_amount.sub(fee))
                assert(0);
            balance.payment_amount = 0.coins;
        }

        if (balance.refund_amount != Amount(0))
            outputs ~= Output(balance.refund_amount,
                genKeyLock(this.conf.funder_pk));

        if (balance.payment_amount != Amount(0))
            outputs ~= Output(balance.payment_amount,
                genKeyLock(this.conf.peer_pk));

        assert(outputs.length > 0);

        foreach (hash, htlc; balance.outgoing_htlcs)
        {
            assert(htlc.amount > Amount(0));
            Lock lock = createLockHTLC(hash, htlc.lock_height,
                this.conf.funder_pk, this.conf.peer_pk);

            Output output = Output(htlc.amount, lock);
            outputs ~= output;
        }

        return outputs;
    }

    /***************************************************************************

        Start collecting close transaction signatures.

        The node will send the counter-party a `requestCloseSig` request,
        with the sequence ID of the last known state.

        The counter-party should return its signature for the closing
        transaction.

        Once the closing multisig is validated, it will be published to
        the blockchain in order to close the channel.

        Params:
            priv_nonce = the private nonce of this node
            peer_nonce = the public nonce of the peer
            fee = amount of fees to include in closing TX

    ***************************************************************************/

    private void collectCloseSignatures (Pair priv_nonce, Point peer_nonce, Amount fee)
    {
        // todo: index is hardcoded
        const utxo = UTXO.getHash(hashFull(this.funding_tx_signed), 0);
        const nofee_outputs = this.buildBalanceOutputs(this.cur_balance);
        auto dummy_closing_tx = createClosingTx(utxo, nofee_outputs);
        dummy_closing_tx.inputs[0].unlock = genKeyUnlock(Signature.init);
        if (!fee.mul(dummy_closing_tx.sizeInBytes))
        {
            this.state = ChannelState.RejectedCollaborativeClose;
            this.onChannelNotify(this.kp.address, this.conf.chan_id,
                this.state, ErrorCode.RejectedClosingFee);
        }

        const outputs = this.buildBalanceOutputs(this.cur_balance, fee);
        this.pending_close.tx = createClosingTx(utxo, outputs);

        const nonce_pair_pk = priv_nonce.V + peer_nonce;
        this.pending_close.our_sig = sign(this.kp.secret, this.conf.pair_pk,
            nonce_pair_pk, priv_nonce.v, this.pending_close.tx);

        const fail_time = Clock.currTime() + this.flash_conf.max_retry_time;
        Result!Signature sig_res = Result!Signature(ErrorCode.Unknown);

        foreach (attempt; 0 .. uint.max)
        {
            const WaitTime = this.backoff.getDelay(attempt).msecs;
            if (Clock.currTime() + WaitTime >= fail_time)
            {
                // timeout
                this.state = ChannelState.RejectedCollaborativeClose;
                this.onChannelNotify(this.kp.address, this.conf.chan_id,
                    this.state, sig_res.error);
                return;
            }

            this.taskman.wait(WaitTime);

            sig_res = this.peer.requestCloseSig(this.kp.address,
                PublicKey(this.peer_pk), this.conf.chan_id, this.cur_seq_id);
            if (sig_res.error)
            {
                log.info("{}: Closing tx signature request rejected: {}",
                    this.kp.address.flashPrettify, sig_res);
                continue;
            }

            // validate it
            if (auto error = this.isInvalidCloseMultiSig(this.pending_close,
                sig_res.value, priv_nonce, peer_nonce))
            {
                log.info("{}: Error during validation: {}. For closing signature: {}",
                    this.kp.address.flashPrettify, error, sig_res.value);

                this.state = ChannelState.RejectedCollaborativeClose;
                this.onChannelNotify(this.kp.address, this.conf.chan_id,
                    this.state, ErrorCode.InvalidSignature);
                return;
            }

            break;
        }

        this.pending_close.peer_sig = sig_res.value;
        this.pending_close.validated = true;

        // todo: schedule this
        log.info("{}: Publishing close tx: {}",
            this.kp.address.flashPrettify, this.pending_close.tx.hashFull.flashPrettify);
        this.txPublisher(this.pending_close.tx);
    }

    /***************************************************************************

        Attempt to collaboratively close the channel.

        The channel will attempt to co-operatively close by offering the
        counter-party to sign a closing transaction which spends directly
        from the funding transaction where the closing transaction is not
        encumbered by any sequence locks.

        This closing transaction will need to be externalized before the
        channel may be considered closed.

        If the counter-party is not collaborative or is non-responsive,
        the node will wait until `cooperative_close_timeout` time has passed
        since the last failed co-operative close request. If this timeout is
        reached the node will forcefully publish the trigger transaction.

        Once the trigger transaction is externalized the node will publish
        the latest update transaction if any, and subsequently will publish the
        settlement transaction. The settlement transaction may only be published
        after `settle_time` blocks were externalized after the trigger/update
        transaction's UTXO was included in the blockchain - this leaves enough
        time for the counter-party to react and publish a newer update &
        settlement transactions in case the closing party tries to cheat by
        publishing a stale update & settlement pair of transactions.

        Params:
            seq_id = the sequence ID.

        Returns:
            the update signature,
            or an error code with an optional error message.

    ***************************************************************************/

    public Result!Point requestCloseChannel (in uint seq_id,
        Point peer_nonce, in Amount fee)
    {
        if (this.state != ChannelState.Open)
            return Result!Point(ErrorCode.ChannelNotOpen,
                format("Channel state is not open: %s", this.state));

        if (seq_id != this.cur_seq_id)
            return Result!Point(ErrorCode.InvalidSequenceID,
                format("requestCloseChannel: expected seq_id: %s. Got: %s",
                    this.cur_seq_id, seq_id));

        // todo: check fee
        // todo: need to calculate *our* balance here and see if we can
        // cover this fee.

        this.state = ChannelState.StartedCollaborativeClose;
        this.onChannelNotify(this.kp.address, this.conf.chan_id, this.state,
            ErrorCode.None);
        Pair priv_nonce = Pair.random();
        Point pub_nonce = priv_nonce.V;

        // todo: there may be a double call here if the first request timed-out
        // and the client sends this request again. We should avoid calling
        // this again.
        this.taskman.setTimer(100.msecs,
        {
            this.collectCloseSignatures(priv_nonce, peer_nonce, fee);
        });

        return Result!Point(pub_nonce);
    }

    /***************************************************************************

        Requests the signature for the closing transaction from this node.

        There must have been a previous `closeChannel` request, otherwise
        the node will return an error.

        Params:
            seq_id = the sequence ID

        Returns:
            the closing transaction signature,
            or an error if something went wrong

    ***************************************************************************/

    public Result!Signature requestCloseSig (in uint seq_id)
    {
        if (this.state != ChannelState.StartedCollaborativeClose &&
            this.state != ChannelState.Closed)
            return Result!Signature(ErrorCode.ChannelNotClosing,
                "Cannot request closing signature before issuing "
                ~ "closeChannel() request");

        if (seq_id != this.cur_seq_id)
            return Result!Signature(ErrorCode.InvalidSequenceID,
                format("requestCloseSig: expected seq_id: %s. Got: %s",
                    this.cur_seq_id, seq_id));

        // todo: handle this edge-case (can occur due to timing issues)
        if (this.pending_close.our_sig == Signature.init)
            return Result!Signature(ErrorCode.SigningInProcess,
                "Close signature not created yet, please try again later");

        return Result!Signature(this.pending_close.our_sig);
    }

    /***************************************************************************

        Checks the validity of the settlement multisig.

        Our partial schnorr signature is combined with the counter-party's
        signature and verified for validity.

        Params:
            settle = the pending settlement transaction which contains our
                own signature.
            peer_sig = the peer's signature which will be combined and validated.
            priv_nonce = the private nonce we've used for signing.
            peer_nonce = the counter-party's public nonce it used for signing.

        Returns:
            null if the signature is valid,
            or an error message if the signature was invalid

    ***************************************************************************/

    private string isInvalidCloseMultiSig (ref PendingClose close,
        in Signature peer_sig, in Pair priv_nonce, in Point peer_nonce)
    {
        const nonce_pair_pk = priv_nonce.V + peer_nonce;
        const close_multi_sig = Signature(nonce_pair_pk,
              close.our_sig.s + peer_sig.s);

        Transaction close_tx
            = close.tx.serializeFull().deserializeFull!Transaction;

        close_tx.inputs[0].unlock = genKeyUnlock(close_multi_sig);

        // note: must always use the execution engine to validate and never
        // try to validate the signatures manually.
        if (auto error = this.engine.execute(
            this.funding_tx_signed.outputs[0].lock, close_tx.inputs[0].unlock,
            close_tx, close_tx.inputs[0]))
            return error;

        // todo: must always validate the tx itself with the validation
        // routine instead of using the engine alone.

        close.tx = close_tx;
        return null;
    }

    /***************************************************************************

        Forwards the error information to previous node if this channel was
        a part of the route

        Params:
            err = Description of the failure

    ***************************************************************************/

    public void forwardPaymentError (OnionError error) @trusted
    {
        if (error.payment_hash in this.payment_hashes ||
            error.payment_hash in this.dropped_htlcs)
        {
            const shared_secret = error.payment_hash in this.payment_hashes ?
                                    this.payment_hashes[error.payment_hash] :
                                    this.dropped_htlcs[error.payment_hash];
            this.dropped_htlcs.remove(error.payment_hash);
            this.taskman.setTimer(100.msecs,
            {
                this.peer.reportPaymentError(PublicKey(this.peer_pk),
                    this.conf.chan_id, error.obfuscate(shared_secret));
            });
        }
    }

    /***************************************************************************

        Returns:
            Most recent ChannelUpdate for our end of the Channel

    ***************************************************************************/

    public ChannelUpdate getChannelUpdate () @safe
    {
        return this.last_update;
    }

    /***************************************************************************

        Update the fees

        Params:
            fixed_fee = Fixed fee that should paid for each payment
            proportional_fee = Proportional fee that should paid for each BOA

    ***************************************************************************/

    public ChannelUpdate updateFees (Amount fixed_fee, Amount proportional_fee)
        @safe
    {
        this.last_update.fixed_fee = fixed_fee;
        this.last_update.proportional_fee = proportional_fee;
        this.last_update.update_idx++;
        this.last_update.sig = this.kp.sign(this.last_update);
        return this.last_update;
    }

    /***************************************************************************

        Update the required HTLC lock delta

        Params:
            htlc_delta = the minimum number of blocks a node requires to be
            added to the expiry of HTLCs

    ***************************************************************************/

    public ChannelUpdate updateHTLCDelta (uint htlc_delta)
    {
        this.last_update.htlc_delta = htlc_delta;
        this.last_update.update_idx++;
        this.last_update.sig = this.kp.sign(this.last_update);
        return this.last_update;
    }

    version (unittest)
    public void waitForUpdateIndex (in uint index)
    {
        // wait until this index is available
        while (index >= this.channel_updates.length)
            this.taskman.wait(100.msecs);

        if (index < this.channel_updates.length)
            log.info("waitForUpdateIndex: index {} is OK compared to updates {}",
                index, this.channel_updates.length);
    }

    // forcefully publish an update transaction with the given index.
    // for use with tests
    version (unittest)
    public Transaction getPublishUpdateIndex (uint index)
    {
        // wait until this update is complete
        while (index >= this.channel_updates.length)
            this.taskman.wait(100.msecs);

        assert(index < this.channel_updates.length);
        const update_tx = this.channel_updates[index].update_tx;
        log.info("{}: Publishing update tx index {}: {}",
            this.kp.address.flashPrettify, index, update_tx.hashFull().flashPrettify);
        this.txPublisher(cast()update_tx);
        return cast()update_tx;
    }

    version (unittest)
    public Transaction getLastSettleTx ()
    {
        return this.channel_updates[$ - 1].settle_tx;
    }

    version (unittest)
    public Transaction getClosingTx ()
    {
        return this.pending_close.tx;
    }
}

/// The closing transaction can spend from the funding transaction when
/// the channel parties want to collaboratively close the channel.
/// It requires both of the parties signatures. For safety reasons,
/// the closing transaction should only be signed once the node marks
/// the channel as 'PendingClose'.
private struct PendingClose
{
    /// The pending close transaction
    private Transaction tx;

    /// Our part of the multisig
    private Signature our_sig;

    /// The peer's part of the multisig
    private Signature peer_sig;

    /// True if the multisig has been validated
    private bool validated;
}

/// Queued incoming payment
private struct IncomingPayment
{
    private uint seq_id;
    private PrivateNonce priv_nonce;
    private PublicNonce peer_nonce;
    private OnionPacket packet;
    private Payload payload;
    private Hash payment_hash;
    private Amount amount;
    private Height height;
    private Height lock_height;
    private Point shared_secret;
}

/// Queued incoming update
private struct IncomingUpdate
{
    private uint seq_id;
    private Output[] outputs;
    private Balance balance;
    private PrivateNonce priv_nonce;
    private PublicNonce peer_nonce;
    private const(Hash)[] secrets;
    private const(Hash)[] revert_htlcs;
}

/// Outgoing payment
private struct OutgoingPayment
{
    private Hash payment_hash;
    private Amount amount;
    private Height lock_height;
    private OnionPacket packet;
    private Height height;
}

/// All the channel metadata which we keep in the DB for storage
private mixin template ChannelMetadata ()
{
    /// The static information about this channel
    public ChannelConfig conf;

    /// Key-pair used for signing and deriving update / settlement key-pairs
    public KeyPair kp;

    /// Whether we are the funder of this channel (`funder_pk == this.kp.V`)
    public bool is_owner;

    /// The public key of the counter-party (for logging)
    public PublicKey peer_pk;

    /// Our private nonce for the first trigger tx
    public PrivateNonce priv_nonce;

    /// The public nonce of the counter-party for the first trigger tx
    public PublicNonce peer_nonce;

    /// Current state of the channel
    private ChannelState state;

    /// Stored when the funding transaction is signed.
    /// For peers they receive this from the blockchain.
    public Transaction funding_tx_signed;

    /// The list of any off-chain updates which happened on this channel
    private UpdatePair[] channel_updates;

    /// Known settle transaction hashes. If any of these are detected on the
    /// blockchain it means the channel should transition to a closed state.
    private Set!Hash known_settle_txs;

    /// Unresolved payment hashes and their associated shared secret
    /// which are part of existing HTLCs
    private Point[Hash] payment_hashes;

    /// Valid when `channel_updates` is not empty, used for the watchtower
    private Hash trigger_utxo;

    /// The current sequence ID
    private uint cur_seq_id;

    /// The current balance of the channel. Initially empty until the
    /// funding tx is externalized.
    private Balance cur_balance;

    /// List of dropped HTLCS
    /// Usefull when routing error packets back to the payment origin
    private Point[Hash] dropped_htlcs;

    /// Ditto
    private PendingClose pending_close;

    /// Incoming payments
    private IncomingPayment[] incoming_payments;

    /// Incoming updates
    private IncomingUpdate[] incoming_updates;

    /// Outgoing payments
    private OutgoingPayment[] outgoing_payments;

    /// Whether there is currently an outbound proposal in progress
    private bool outbound_in_progress;

    /// Last known block height
    private Height height;

    /// Learned secrets that match pending HTLCs
    private const(Hash)[] secrets;

    /// Any HTLCs which still need to be reverted
    private const(Hash)[] revert_htlcs;

    /// Most recent ChannelUpdate for our end of the Channel
    private ChannelUpdate last_update;

    /// The height at which the latest update transaction was detected on
    /// the blockchain, which begins a timeout after which a settlement tx
    /// may be published to the blockchain.
    private Height update_ext_height;
}
