/*******************************************************************************

    The `Ledger` class binds together other components to provide a consistent
    view of the state of the node.

    The Ledger acts as a bridge between other components, e.g. the `UTXOSet`,
    `EnrollmentManager`, `IBlockStorage`, etc...
    While the `Node` is the main object in Agora, the `Ledger` is the second
    most important class, handling all business logic, relying on the the `Node`
    for anything related to network communicatiion.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.node.Ledger;

import agora.common.Amount;
import agora.common.Config;
import agora.common.ManagedDatabase;
import agora.common.Set;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.protocol.Data;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Params;
import agora.consensus.data.PreImageInfo;
import agora.consensus.data.Transaction;
import agora.consensus.state.UTXOSet;
import agora.consensus.EnrollmentManager;
import agora.consensus.Fee;
import agora.consensus.validation;
import agora.consensus.validation.Block : validateBlockTimeOffset;
import agora.consensus.Fee;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.network.Clock;
import agora.node.BlockStorage;
import agora.node.TransactionPool;
import agora.script.Engine;
import agora.script.Lock;
import agora.serialization.Serializer;
import agora.utils.Log;
import agora.utils.PrettyPrinter;

import std.algorithm;
import std.algorithm.searching : maxElement;
import std.conv : to;
import std.exception;
import std.format;
import std.range;
import std.typecons : Nullable, nullable;

import core.time : Duration, seconds;

version (unittest)
{
    import agora.consensus.data.genesis.Test: genesis_validator_keys;
    import agora.utils.Test;
}

/// Ditto
public class Ledger
{
    /// Logger instance
    protected Logger log;

    /// Script execution engine
    private Engine engine;

    /// data storage for all the blocks
    private IBlockStorage storage;

    /// Pool of transactions to pick from when generating blocks
    private TransactionPool pool;

    /// TX Hashes Ledger encountered but dont have in the pool
    private Set!Hash unknown_txs;

    /// The last block in the ledger
    private Block last_block;

    /// UTXO set
    private UTXOCache utxo_set;

    // Clock instance
    private Clock clock;

    /// Enrollment manager
    private EnrollmentManager enroll_man;

    /// Property for Enrollment manager
    @property public EnrollmentManager enrollment_manager () @safe nothrow
    {
        return this.enroll_man;
    }

    /// If not null call this delegate
    /// A block was externalized
    private void delegate (in Block, bool) @safe onAcceptedBlock;

    /// Parameters for consensus-critical constants
    private immutable(ConsensusParams) params;

    /// The checker of transaction data payload
    private FeeManager fee_man;

    /// The new block time_offset has to be greater than the previous block time_offset,
    /// but less than current time + block_time_offset_tolerance
    public Duration block_time_offset_tolerance;

    /// Enrollment keys for unknown preimages for the next height
    private Set!Hash enrolls_keys_for_unknown_preimages;

    /***************************************************************************

        Constructor

        Params:
            params = the consensus-critical constants
            engine = script execution engine
            utxo_set = the set of unspent outputs
            storage = the block storage
            enroll_man = the enrollmentManager
            pool = the transaction pool
            fee_man = the checker of data payload
            clock = the clock instance
            block_time_offset_tolerance = the proposed block time_offset should be less
                than curr_time_offset + block_time_offset_tolerance
            onAcceptedBlock = optional delegate to call
                              when a block was added to the ledger

    ***************************************************************************/

    public this (immutable(ConsensusParams) params,
        Engine engine, UTXOCache utxo_set, IBlockStorage storage,
        EnrollmentManager enroll_man, TransactionPool pool,
        FeeManager fee_man, Clock clock,
        Duration block_time_offset_tolerance = 60.seconds,
        void delegate (in Block, bool) @safe onAcceptedBlock = null)
    {
        this.log = Logger(__MODULE__);
        this.params = params;
        this.engine = engine;
        this.utxo_set = utxo_set;
        this.storage = storage;
        this.enroll_man = enroll_man;
        this.pool = pool;
        this.onAcceptedBlock = onAcceptedBlock;
        this.fee_man = fee_man;
        this.clock = clock;
        this.block_time_offset_tolerance = block_time_offset_tolerance;
        this.storage.load(params.Genesis);

        // ensure latest checksum can be read
        this.last_block = this.storage.readLastBlock();
        log.info("Last known block: #{} ({})", this.last_block.header.height,
                 this.last_block.header.hashFull());

        Block gen_block = this.storage.readBlock(Height(0));
        if (gen_block != params.Genesis)
            throw new Exception("Genesis block loaded from disk is " ~
                "different from the one in the config file");
        foreach (const ref e; gen_block.header.enrollments)
            if (e.cycle_length != params.ValidatorCycle)
                throw new Exception("ConsensusParams are not consistent with Genesis");

        if (this.utxo_set.length == 0
            || this.enroll_man.validator_set.countActive(this.last_block.header.height + 1) == 0)
        {
            this.utxo_set.clear();
            this.enroll_man.removeAllValidators();

            // Calling `addValidatedBlock` will reset this value
            const HighestHeight = this.last_block.header.height;
            foreach (height; 0 .. HighestHeight + 1)
            {
                this.replayStoredBlock(this.storage.readBlock(Height(height)));
            }
        }
    }

    /***************************************************************************

        Returns the last block in the `Ledger`

        Returns:
            last block in the `Ledger`

    ***************************************************************************/

    public ref const(Block) getLastBlock () const scope @safe @nogc nothrow pure
    {
        return this.last_block;
    }

    /***************************************************************************

        Returns:
            The highest block height known to this Ledger

    ***************************************************************************/

    public Height getBlockHeight () const scope @safe @nogc nothrow pure
    {
        return this.last_block.header.height;
    }

    /***************************************************************************

        Returns:
            A list of validators that can sign the block at `height`

    ***************************************************************************/

    public ValidatorInfo[] getValidators (in Height height) scope @safe
    {
        auto result = this.enroll_man.validator_set.getValidators(height);
        if (result.length == 0)
            throw new Exception("Ledger.getValidators didn't find any validator");
        return result;
    }

    /***************************************************************************

        Add a block to the ledger.

        If the block fails verification, it is not added to the ledger.

        Params:
            block = the block to add

        Returns:
            true if the block was accepted

    ***************************************************************************/

    public bool acceptBlock (in Block block,
        string file = __FILE__, size_t line = __LINE__) @safe
    {
        if (auto fail_reason = this.validateBlock(block, file, line))
        {
            log.trace("Rejected block: {}: {}", fail_reason, block.prettify());
            return false;
        }

        const old_count = this.enroll_man.validator_set.countActive(block.header.height);

        this.storage.saveBlock(block);
        this.addValidatedBlock(block);

        const new_count = this.enroll_man.validator_set.countActive(block.header.height + 1);
        // there was a change in the active validator set
        const bool validators_changed = block.header.enrollments.length > 0
            || new_count != old_count;
        if (this.onAcceptedBlock !is null)
            this.onAcceptedBlock(block, validators_changed);

        return true;
    }

    /***************************************************************************

        Update the Schnorr multi-signature for an externalized block
        in the Ledger.

        Params:
            header = block header to be updated

    ***************************************************************************/

    public void updateBlockMultiSig (in BlockHeader header) @safe
    {
        this.storage.updateBlockSig(header.height, header.hashFull(),
            header.signature, header.validators);

        if (header.height == this.last_block.header.height)
            this.last_block = this.storage.readLastBlock();
    }

    /***************************************************************************

        Called when a new transaction is received.

        If the transaction is accepted it will be added to
        the transaction pool. If there are enough valid transactions
        in the pool, a block will be created.

        If the transaction is invalid, it's rejected and false is returned.

        Params:
            tx = the received transaction

        Returns:
            true if the transaction is valid and was added to the pool

    ***************************************************************************/

    public bool acceptTransaction (Transaction tx) @safe
    {
        const Height expected_height = this.getBlockHeight() + 1;
        string reason;

        if (tx.isCoinbase ||
            (reason = tx.isInvalidReason(this.engine,
                this.utxo_set.getUTXOFinder(),
                expected_height, &this.fee_man.check)) !is null ||
            !this.pool.add(tx))
        {
            log.info("Rejected tx. Reason: {}. Tx: {}",
                reason !is null ? reason : "double-spend/coinbase", tx);
            return false;
        }
        // If we were looking for this TX, stop
        this.unknown_txs.remove(tx.hashFull());
        return true;
    }

    /***************************************************************************

        Add a validated block to the Ledger.

        This will add all of the block's outputs to the UTXO set, as well as
        any enrollments that may be present in the block to the validator set.

        If not null call the `onAcceptedBlock` delegate.

        Params:
            block = the block to add

    ***************************************************************************/

    private void addValidatedBlock (in Block block) @safe
    {
        log.info("Beginning externalization of block #{}", block.header.height);
        log.info("Transactions: {} - Enrollments: {}",
                 block.txs.length, block.header.enrollments.length);
        log.info("Validators: Active: {} - Signing: {} - Slashed: {}",
                 enroll_man.validator_set.countActive(block.header.height + 1),
                 block.header.validators,
                 block.header.missing_validators);
        // Keep track of the fees generated by this block, before updating the
        // validator set
        this.accumulateFees(block);

        ManagedDatabase.beginBatch();
        {
            // rollback on failure within the scope of the db transactions
            scope (failure) ManagedDatabase.rollback();
            this.updateUTXOSet(block);
            this.updateValidatorSet(block);
            ManagedDatabase.commitBatch();
        }

        // Clear the unknown TXs every round (clear() is not @safe)
        this.unknown_txs = Set!Hash.init;

        // Update the known "last block"
        this.last_block = deserializeFull!Block(serializeFull(block));
    }

    /***************************************************************************

        Update the ledger state from a block which was read from storage

        Params:
            block = block to update the state from

    ***************************************************************************/

    protected void replayStoredBlock (in Block block) @safe
    {
        // Make sure our data on disk is valid
        if (auto fail_reason = this.validateBlock(block))
            throw new Exception("A block loaded from disk is invalid: " ~
                fail_reason);

        this.addValidatedBlock(block);
    }

    /***************************************************************************

        Update the UTXO set based on the block's transactions

        Params:
            block = the block to update the UTXO set with

    ***************************************************************************/

    protected void updateUTXOSet (in Block block) @safe
    {
        const height = block.header.height;
        // add the new UTXOs
        block.txs.each!(tx => this.utxo_set.updateUTXOCache(tx, height,
            this.params.CommonsBudgetAddress));

        // remove the TXs from the Pool
        block.txs.each!(tx => this.pool.remove(tx));

        // Slashing requires the validator set, however there is no slashing
        // in genesis, and the validator set isn't ready yet.
        if (block.header.height != 0)
            this.updateSlashedUTXOSet(block);
    }

    /***************************************************************************

        Update the UTXOs of validators that are to be slashed

        Params:
            block = the block to update the UTXO set with

    ***************************************************************************/

    protected void updateSlashedUTXOSet (in Block block) @safe
    {
        Hash[] validator_utxos;
        this.getMissingValidatorsUTXOs(validator_utxos,
            block.header.height, block.header.missing_validators);
        foreach (utxo; validator_utxos)
        {
            UTXO utxo_value;
            if (!this.utxo_set.peekUTXO(utxo, utxo_value))
                assert(0, "UTXO for the slashed validator not found!");

            auto remain_amount = Amount(utxo_value.output.value);
            remain_amount.sub(this.params.SlashPenaltyAmount);
            Transaction slashing_tx = Transaction(
                [Input(utxo)],
                [
                    Output(this.params.SlashPenaltyAmount,
                        this.params.CommonsBudgetAddress),
                    Output(remain_amount, utxo_value.output.address),
                ]);
            this.utxo_set.updateUTXOCache(slashing_tx, block.header.height,
                this.params.CommonsBudgetAddress);
        }
    }

    /***************************************************************************

        Update the active validator set

        Params:
            block = the block to update the Validator set with

    ***************************************************************************/

    protected void updateValidatorSet (in Block block) @safe
    {

        PublicKey pubkey = this.enroll_man.getEnrollmentPublicKey();
        UTXO[Hash] utxos = this.utxo_set.getUTXOs(pubkey);
        foreach (idx, ref enrollment; block.header.enrollments)
        {
            UTXO utxo;
            if (!this.utxo_set.peekUTXO(enrollment.utxo_key, utxo))
                assert(0);

            if (auto r = this.enroll_man.addValidator(enrollment, utxo.output.address,
                block.header.height, &this.utxo_set.peekUTXO, utxos))
            {
                log.fatal("Error while adding a new validator: {}", r);
                log.fatal("Enrollment #{}: {}", idx, enrollment);
                log.fatal("Validated block: {}", block);
                assert(0);
            }
        }

        const Height next = block.header.height + 1;
        this.updateSlashedValidatorSet(block);
        auto keys = this.getValidators(next).map!(vi => vi.address).array();
        this.log.trace("Update validator lookup maps at height {}: {}", next, keys);
        this.enroll_man.keymap.update(next, keys);
    }

    /***************************************************************************

        Update the validators that are to be slashed

        Params:
            block = the block to update the Validator set with

    ***************************************************************************/

    protected void updateSlashedValidatorSet (in Block block) @safe
    {
        if (block.header.height == 0)
            return;

        Hash[] validators_utxos;
        this.getMissingValidatorsUTXOs(validators_utxos,
            block.header.height, block.header.missing_validators);
        foreach (utxo; validators_utxos)
        {
            log.warn("Slashing validator UTXO {} at height {}",
                     utxo, block.header.height);
            this.enroll_man.validator_set.slashValidator(utxo, block.header.height);
        }
    }

    /***************************************************************************

        Checks whether the `tx` is an acceptable double spend transaction.

        If `tx` is not a double spend transaction, then returns true.
        If `tx` is a double spend transaction, and its fee is considerable higher
        than the existing double spend transactions, then returns true.
        Otherwise this function returns false.

        Params:
            tx = transaction
            threshold_pct = percentage by which the fee of the new transaction has
              to be higher, than the previously highest double spend transaction

        Returns:
            whether the `tx` is an acceptable double spend transaction

    ***************************************************************************/

    public bool isAcceptableDoubleSpent (in Transaction tx, ubyte threshold_pct) @safe
    {

        Amount tx_fee;
        if (fee_man.getAdjustedTXFee(tx, &utxo_set.peekUTXO, tx_fee) != null)
            return false;

        // only consider a double spend transaction, if its fee is
        // considerably higher than the current highest fee
        auto fee_threshold = getDoubleSpentHighestFee(tx);

        // if the fee_threshold is null, it means there won't be any double
        // spend transactions, after this transaction is added to the pool
        if (!fee_threshold.isNull())
            fee_threshold.get().percentage(threshold_pct + 100);

        if (!fee_threshold.isNull() &&
            (!tx_fee.isValid() || tx_fee < fee_threshold.get()))
            return false;

        return true;
    }

    /***************************************************************************

        Create the Coinbase TX for this nomination round and append it to the
        tx_set

        Params:
            height = block height
            tot_fee = Total fee amount (incl. data)
            tot_data_fee = Total data fee amount
            missing_validators = MPVs

        Returns:
            List of expected Coinbase TXs

    ***************************************************************************/

    public Transaction[] getCoinbaseTX (in Height height, in Amount tot_fee, in Amount tot_data_fee,
        in uint[] missing_validators) nothrow @safe
    {
        UTXO[] stakes;
        this.enroll_man.getValidatorStakes(height, &this.utxo_set.peekUTXO, stakes,
            missing_validators);
        const commons_fee = this.fee_man.getCommonsBudgetFee(tot_fee,
            tot_data_fee, stakes);

        Output[] coinbase_tx_outputs;
        // pay the commons budget
        if (commons_fee > Amount(0))
            coinbase_tx_outputs ~= Output(commons_fee,
                this.params.CommonsBudgetAddress, OutputType.Coinbase);

        // pay the validator for the past blocks
        if (auto payouts = this.fee_man.getAccumulatedFees(height))
            foreach (pair; payouts.byKeyValue())
                if (pair.value > Amount(0))
                    coinbase_tx_outputs ~= Output(pair.value, pair.key, OutputType.Coinbase);
        coinbase_tx_outputs.sort;
        return coinbase_tx_outputs.length > 0 ?
            [ Transaction([Input(height)], coinbase_tx_outputs) ] : [];
    }

    /// Error message describing the reason of validation failure
    public static enum InvalidConsensusDataReason : string
    {
        NoTransactions = "Transaction set doesn't contain any transactions",
        NotEnoughValidators = "Enrollment: Insufficient number of active validators",
        MayBeValid = "May be valid",
        OnlyCoinbaseTX = "Transaction set only includes a Coinbase transaction",
        TooManyMPVs = "More MPVs than active enrollments",
        NoUTXO = "Couldn't find UTXO for one or more Enrollment",
        NotInPool = "Transaction is not in the pool",

    }

    /***************************************************************************

        Create the Coinbase TX for this nomination round

        Params:
            tx_set = Transaction set to generate the CoinBase TX for
            missing_validators = MPVs

        Returns:
            List of expected Coinbase TXs

    ***************************************************************************/

    public Transaction[] getCoinbaseTX (in Transaction[] tx_set,
        in uint[] missing_validators) nothrow @safe
    {
        Amount tot_fee, tot_data_fee;
        if (auto fee_res = this.fee_man.getTXSetFees(tx_set, &this.utxo_set.peekUTXO, tot_fee, tot_data_fee))
            assert(0, fee_res);
        return this.getCoinbaseTX(this.last_block.header.height + 1, tot_fee, tot_data_fee, missing_validators);
    }

    /***************************************************************************

        Check whether the consensus data is valid.

        Params:
            data = consensus data
            initial_missing_validators = missing validators at the beginning of
               the nomination round

        Returns:
            the error message if validation failed, otherwise null

    ***************************************************************************/

    public string validateConsensusData (in ConsensusData data,
        in uint[] initial_missing_validators) @trusted nothrow
    {
        const validating = this.getBlockHeight() + 1;
        auto utxo_finder = this.utxo_set.getUTXOFinder();

        if (!data.tx_set.length)
            return InvalidConsensusDataReason.NoTransactions;

        Transaction[] tx_set;
        if (auto fail_reason = this.getValidTXSet(data, tx_set))
            return fail_reason;

        // av   == active validators (this block)
        // avnb == active validators next block
        // The consensus data is for the creation of the next block,
        // so 'this block' means "current height + 1". While the ConsensusData
        // does not contain information about what block we are validating,
        // we assume that it's the block after the currently externalized one.
        size_t av   = enroll_man.validator_set.countActive(validating);
        size_t avnb = enroll_man.validator_set.countActive(validating + 1);

        // First we make sure that we do not slash too many validators,
        // as slashed validators cannot sign a block.
        // If there are 6 validators, and we're slashing 5 of them,
        // av = 6, missing_validators.length = 5, and `6 < 5 + 1` is still `true`.
        if (av < (data.missing_validators.length + Enrollment.MinValidatorCount))
            return InvalidConsensusDataReason.NotEnoughValidators;

        // We're trying to slash more validators that there are next block
        // FIXME: this check isn't 100% correct: we should check which validators
        // we are slashing. It could be that our of 5 validators, 3 are expiring
        // this round, and none of them have revealed their pre-image, in which
        // case the 3 validators we slash should not block externalization.
        if (avnb < data.missing_validators.length)
            return InvalidConsensusDataReason.TooManyMPVs;
        // FIXME: See above comment
        avnb -= data.missing_validators.length;

        // We need to make sure that we externalize a block that allows for the
        // chain to make progress, otherwise we'll be stuck forever.
        if ((avnb + data.enrolls.length) < Enrollment.MinValidatorCount)
            return InvalidConsensusDataReason.NotEnoughValidators;

        foreach (const ref enroll; data.enrolls)
        {
            UTXO utxo_value;
            if (!this.utxo_set.peekUTXO(enroll.utxo_key, utxo_value))
                return InvalidConsensusDataReason.NoUTXO;
            if (auto fail_reason = this.enroll_man.isInvalidCandidateReason(
                enroll, utxo_value.output.address, validating, utxo_finder))
                return fail_reason;
        }

        if (auto fail_reason = this.validateSlashingData(validating, data, initial_missing_validators))
            return fail_reason;

        return validateBlockTimeOffset(last_block.header.time_offset, data.time_offset,
            clock.networkTime(), block_time_offset_tolerance);
    }

    /***************************************************************************

        Check whether the slashing data is valid.

        Params:
            height = height
            data = consensus data
            initial_missing_validators = missing validators at the beginning of
               the nomination round

        Returns:
            the error message if validation failed, otherwise null

    ***************************************************************************/

    public string validateSlashingData (in Height height, in ConsensusData data,
        in uint[] initial_missing_validators) @safe nothrow
    {
        if (auto res = this.isInvalidPreimageRootReason(height, data.missing_validators, initial_missing_validators))
            return res;

        return this.isSelfSlashing(height, data);
    }

    /***************************************************************************

        Check if the consensus data has the information that is slashing
        a node itself

        Params:
            height = the height for which we want to check self slashing
            data = consensus data

        Returns:
            error string, if node is trying to slash itself, null otherwise

    ***************************************************************************/

    public string isSelfSlashing (in Height height, in ConsensusData data) @safe nothrow
    {
        const index = this.enroll_man.getIndexOfEnrollment(height);
        return (index != ulong.max && !data.missing_validators.find(index).empty) ?
            "Node is attempting to slash itself" : null;
    }

    /***************************************************************************

        Check whether the block is valid.

        Params:
            block = the block to check

        Returns:
            the error message if block validation failed, otherwise null

    ***************************************************************************/

    public string validateBlock (in Block block,
        string file = __FILE__, size_t line = __LINE__) nothrow @safe
    {
        // If it's the genesis block, we only need to validate it for syntactic
        // correctness, no need to check signatures.
        if (block.header.height == 0)
            return block.isGenesisBlockInvalidReason();

        // Validate the block syntactically first, so we weed out obviously-wrong
        // blocks without complex computation.
        if (auto reason = block.isInvalidReason(
                this.engine, this.last_block.header.height,
                this.last_block.header.hashFull,
                this.utxo_set.getUTXOFinder(),
                &this.fee_man.check,
                this.enroll_man.getEnrollmentFinder(),
                block.header.validators.count,
                this.last_block.header.time_offset,
                cast(ulong) this.clock.networkTime() - this.params.GenesisTimestamp,
                block_time_offset_tolerance))
            return reason;

        try
        {
            if (block.header.random_seed != this.getRandomSeed(block.header.height, block.header.missing_validators))
                return "Block: Header's random seed does not match that of known pre-images";
        }
        catch (Exception exc)
        {
            this.log.error("validateBlock: Exception thrown by getRandomSeed while externalizing valid block: {}", exc);
            return "Internal error: Could not calculate random seed at current height";
        }

        auto expected_cb_txs = this.getCoinbaseTX(block.txs, block.header.missing_validators);
        auto incoming_cb_txs = block.txs.filter!(tx => tx.isCoinbase);
        if (!isPermutation(expected_cb_txs, incoming_cb_txs))
            return "Invalid Coinbase transaction";

        // Finally, validate the signatures
        return this.validateBlockSignature(block);
    }

    /***************************************************************************

        Validate the signature of a block

        This validate that the signature in a block header is consistent with
        the enrolled validators, and cryptographically correct.
        Note that since this requires to know which nodes are validators,
        this method is contextful and can only guarantee the signature
        of the next block, as the validator set might change after that.

        Implementation_details:
          A block signature is an Schnorr signature. Schnorr signatures are
          usually a pair `(R, s)`, consisting of a point `R` and a scalar `s`.

          The signature is done on the block header, with the two fields
          used to store signatures (`validators` and `signature`) excluded.

          To allow for nodes to independently generate compatible signatures
          without an additional protocol, nodes need to know the set of signers
          and their `R`, which we refer to as signature noise.

          The set of signers is defined as all the validators having revealed
          a pre-image. For this reason, pre-images are allowed and encouraged
          to be revealed earlier than they are needed (although not too early).

          With the set of signers known, we derive the block-specific `R`
          by adding the `R` used in the enrollment to `p * B`, where `p` is
          the pre-image reduced to a scalar and `B` is Curve25519 base point.

          Hence, the signature present in the block is actually just the
          aggregated `s`. To verify this signature, we need to store which
          nodes actually signed, this is stored in the header's
          `validators` field.

        Params:
            block = the block to verify the signature of

        Returns:
            the error message if block validation failed, otherwise null

    ***************************************************************************/

    private string validateBlockSignature (in Block block) @safe nothrow
    {
        import agora.crypto.ECC;
        import agora.crypto.Schnorr;

        Point sum_K;
        Point sum_R;
        const Scalar challenge = hashFull(block);
        ValidatorInfo[] validators;
        try
            validators = this.getValidators(block.header.height);
        catch (Exception exc)
        {
            this.log.error("Exception thrown by getActiveValidatorPublicKey while externalizing valid block: {}", exc);
            return "Internal error: Could not list active validators at current height";
        }

        assert(validators.length == block.header.validators.count);
        foreach (idx, validator; validators)
        {
            const K = validator.address;
            assert(K != PublicKey.init, "Could not find the public key associated with a validator");

            if (!block.header.validators[idx])
            {
                // This is not an error, we might just receive the signature later
                log.trace("Block#{}: Validator {} (idx: {}) has not yet signed",
                          block.header.height, K, idx);
                continue;
            }

            const CR = this.enroll_man.getCommitmentNonce(K, block.header.height);  // commited R
            if (CR == Point.init)
            {
                log.error("Block#{}: Validator {} (idx: {}) Couldn't find commitment for this validator",
                          block.header.height, K, idx);
                return "Block: Couldn't find commitment for this validator";
            }
            const preimage_info = this.enroll_man.validator_set.getPreimageAt(
                this.enroll_man.validator_set.getEnrollmentForKey(block.header.height, K), block.header.height);
            if (preimage_info.hash == Hash.init)
            {
                log.error("Block#{}: Validator {} (idx: {}) Couldn't find pre-image for validator",
                          block.header.height, K, idx);
                return "Block: Couldn't find pre-image for validator";
            }
            Point R = CR + Scalar(preimage_info.hash).toPoint();
            sum_K = sum_K + K;
            sum_R = sum_R + R;
        }

        assert(sum_K != Point.init, "Block has validators but no signature");

        if (sum_R != block.header.signature.R)
        {
            log.error("Block#{}: Signature's `R` mismatch: Expected {}, got {}",
                      block.header.height, sum_R, block.header.signature.R);
            return "Block: Invalid schnorr signature (R)";
        }
        if (!verify(block.header.signature, challenge, sum_K))
        {
            log.error("Block#{}: Invalid signature: {}", block.header.height,
                      block.header.signature);
            return "Block: Invalid signature";
        }

        return null;
    }

    /***************************************************************************

        Get a range of blocks, starting from the provided block height.

        Params:
            start_height = the starting block height to begin retrieval from

        Returns:
            the range of blocks starting from start_height

    ***************************************************************************/

    public auto getBlocksFrom (Height start_height) @safe nothrow
    {
        start_height = min(start_height, this.getBlockHeight() + 1);

        // Call to `Height.value` to work around
        // https://issues.dlang.org/show_bug.cgi?id=21583
        return iota(start_height.value, this.getBlockHeight() + 1)
            .map!(idx => this.storage.readBlock(Height(idx)));
    }

    /***************************************************************************

        Get the random seed reduced from the preimages of validators
        except the provided 'missing_validators'.

        Params:
            height = the desired block height to look up the hash for
            missing_validators = the validators that did not reveal their
                preimages for the height

        Returns:
            The random seed for all validators not in `missing_validators`

        Throws:
            If some pre-images are not known.

    ***************************************************************************/

    public Hash getRandomSeed (in Height height, in uint[] missing_validators)
        @safe
    {
        auto validators = this.getValidators(height);

        // A case where a > b should never happen, but better be conservative
        if (missing_validators.length >= validators.length)
            throw new Exception("Ledger.getRandomSeed() called with all-missing validators");

        // Safety check, as the order will affect `missing_validators`
        assert(missing_validators.isStrictlyMonotonic());
        assert(validators.isStrictlyMonotonic!((a, b) => a.utxo < b.utxo));

        auto signing = validators
            // Filter out entries in `missing_validators`
            .enumerate.filter!(en => !missing_validators.canFind(en.index));

        // Ideally, the following should never happen, as we would catch this
        // before we reach this point, but this safety checks ensures we don't
        // generate a wrong random seed (we would otherwise hash in `Hash.init`
        // or trigger an assertion failure in `PreImageInfo.opIndex`).
        bool missing = false;
        foreach (entry; signing.save.filter!(en => en.value.preimage.height < height))
        {
            log.error("Validator {} (index: {}, address: {}) missing pre-image for height {} (known: {})",
                      entry.value.utxo, entry.index, entry.value.address,
                      height, entry.value.preimage.height);
            missing = true;
        }
        if (missing)
            throw new Exception("Requested pre-images for validators that are not yet known");

        return validators
            // Filter out entries in `missing_validators`
            .enumerate.filter!(en => !missing_validators.canFind(en.index))
            // We made sure in the previous `foreach` that `height >= pi.height`
            // Note that map is needed for`reduce` to be able to deduce the seed type
            .map!(en => en.value.preimage[height])
            // Generate the final value
            .reduce!((a , b) => hashMulti(a, b));
    }

    /***************************************************************************

        Calculate and accumulate fees that will be paid to Validators from this
        block

        Params:
            block = new block

    ***************************************************************************/

    public void accumulateFees (in Block block) @safe
    {
        if (block.header.height == Height(0))
        {
            this.fee_man.clearAccumulatedFees();
            return;
        }

        UTXO[] stakes;
        this.enroll_man.getValidatorStakes(block.header.height, &this.utxo_set.peekUTXO, stakes,
            block.header.missing_validators);
        this.fee_man.accumulateFees(block, stakes, &this.utxo_set.peekUTXO);
    }

    /***************************************************************************

        Returns the highest fee among all the transactions which would be
        considered as a double spent, if `tx` transaction was in the transaction
        pool.

        If adding `tx` to the transaction pool would not result in double spent
        transaction, then the return value is Nullable!Amount().

        Params:
            tx = transaction

        Returns:
            the highest fee among all the transactions which would be
            considered as a double spend, if `tx` transaction was in the
            transaction pool.

    ***************************************************************************/

    public Nullable!Amount getDoubleSpentHighestFee (in Transaction tx) @safe
    {
        Set!Hash tx_hashes;
        pool.gatherDoubleSpentTXs(tx, tx_hashes);

        const(Transaction)[] txs;
        foreach (const tx_hash; tx_hashes)
        {
            const tx_ret = this.pool.getTransactionByHash(tx_hash);
            if (tx_ret != Transaction.init)
                txs ~= tx_ret;
        }

        if (!txs.length)
            return Nullable!Amount();

        return nullable(txs.map!((tx)
            {
                Amount tot_fee;
                fee_man.getAdjustedTXFee(tx, &utxo_set.peekUTXO, tot_fee);
                return tot_fee;
            }).maxElement());
    }

    /***************************************************************************

        Get a transaction from pool by hash

        Params:
            tx = the transaction hash

        Returns:
            Transaction or Transaction.init

    ***************************************************************************/

    public Transaction getTransactionByHash (in Hash hash) @trusted nothrow
    {
        return this.pool.getTransactionByHash(hash);
    }

    /***************************************************************************

        Get the valid TX set that `data` is representing

        Params:
            data = consensus value
            tx_set = buffer to write the found TXs

        Returns:
            `null` if node can build a valid TX set, a string explaining
            the reason otherwise.

    ***************************************************************************/

    public string getValidTXSet (in ConsensusData data, ref Transaction[] tx_set)
        @safe nothrow
    {
        const expect_height = this.getBlockHeight() + 1;
        auto utxo_finder = this.utxo_set.getUTXOFinder();
        bool[Hash] local_unknown_txs;

        Amount tot_fee, tot_data_fee;
        scope checkAndAcc = (in Transaction tx, Amount sum_unspent) {
            const err = this.fee_man.check(tx, sum_unspent);
            if (!err && !tx.isCoinbase)
            {
                tot_fee.add(sum_unspent);
                tot_data_fee.add(
                    this.fee_man.getDataFee(tx.payload.length));
            }
            return err;
        };

        foreach (const ref tx_hash; data.tx_set)
        {
            auto tx = this.pool.getTransactionByHash(tx_hash);
            if (tx == Transaction.init)
                local_unknown_txs[tx_hash] = true;
            else if (auto fail_reason = tx.isInvalidReason(this.engine,
                utxo_finder, expect_height, checkAndAcc))
                return fail_reason;
            else
                tx_set ~= tx;
        }

        auto expected_cb_txs = this.getCoinbaseTX(expect_height, tot_fee,
            tot_data_fee, data.missing_validators);
        auto excepted_cb_hashes = expected_cb_txs.map!(tx => tx.hashFull());
        assert(expected_cb_txs.length <= 1);

        // Because CB TXs are never in the pool, they will always end up in
        // local_unknown_txs. There should be atleast expected_cb_txs.length
        // number of unknown txs.
        if (!expected_cb_txs.empty()
                && local_unknown_txs.length <= expected_cb_txs.length)
            foreach (tx_hash; excepted_cb_hashes)
                if (tx_hash !in local_unknown_txs)
                    return "Invalid Coinbase transaction";

        // If we met our CB expectations, remove them.
        excepted_cb_hashes.each!(tx => local_unknown_txs.remove(tx));
        expected_cb_txs.each!(tx => tx_set ~= tx);

        if (local_unknown_txs.length > 0)
        {
            local_unknown_txs.byKey.each!(tx => this.unknown_txs.put(tx));
            return InvalidConsensusDataReason.MayBeValid;
        }

        // Check if we have any real TXs
        if (tx_set.any!(tx => !tx.isCoinbase))
            return null;
        return InvalidConsensusDataReason.OnlyCoinbaseTX;
    }

    /***************************************************************************

        Get a set of TX Hashes that Ledger is missing

        Returns:
            set of TX Hashes that Ledger is missing

    ***************************************************************************/

    public Set!Hash getUnknownTXHashes () @safe nothrow
    {
        return this.unknown_txs;
    }

    /***************************************************************************

        Get the enrollment keys for unknown preimages

        Returns:
            the enrollment keys for unknown preimages

    ***************************************************************************/

    public Set!Hash getEnrollKeysForUnknownPreimages () @safe nothrow
    {
        return this.enrolls_keys_for_unknown_preimages;
    }
    /***************************************************************************

        Get the UTXOs of the validators that do not reveal their pre-images
        by indices

        Params:
            validators_utxos = will contain the UTXOs ot the validators
            height = curent block being created
            missing_validators = indices of validators being slashed

    ***************************************************************************/

    private void getMissingValidatorsUTXOs (ref Hash[] validators_utxos,
        in Height height, const uint[] missing_validators) @safe nothrow
    {
        validators_utxos.length = 0;
        () @trusted { assumeSafeAppend(validators_utxos); }();

        Hash[] keys;
        if (!this.enroll_man.getEnrolledUTXOs(height, keys))
            assert(0, "Could not retrieve enrollments");

        foreach (idx; missing_validators)
        {
            validators_utxos ~= keys[idx];
        }
    }

    /***************************************************************************

        Check if a validator has a pre-image for the height

        Params:
            height = the desired block height to look up the hash for
            utxo_key = the UTXO key idendifying a validator

        Returns:
            true if the validator has revealed its preimage for the provided
                block height or if current node

    ***************************************************************************/

    private bool hasRevealedPreimage (in Height height, in Hash utxo_key)
        @safe nothrow
    {
        if (utxo_key == this.enroll_man.getEnrollmentKey())
            return true; // this is current Ledger node

        auto preimage = this.enroll_man.getValidatorPreimage(utxo_key);
        auto enrolled = this.enroll_man.validator_set.getEnrolledHeight(height, preimage.utxo);
        assert(height >= enrolled);
        return preimage.height >= height;
    }

    /***************************************************************************

        Check if information for pre-images and slashed validators is valid

        Params:
            height = the height of proposed block
            missing_validators = list of indices to the validator UTXO set
                which have not revealed the preimage
            missing_validators_higher_bound = missing validators at the beginning of
               the nomination round

        Returns:
            `null` if the information is valid at the proposed height,
            otherwise a string explaining the reason it is invalid.

    ***************************************************************************/

    private string isInvalidPreimageRootReason (in Height height,
        in uint[] missing_validators, in uint[] missing_validators_higher_bound) @safe nothrow
    {
        import std.algorithm.setops : setDifference;

        Hash[] keys;
        if (!this.enroll_man.getEnrolledUTXOs(height, keys) || keys.length == 0)
            assert(0, "Could not retrieve enrollments / no enrollments found");

        uint[] missing_validators_lower_bound;
        foreach (idx, key; keys)
        {
            if (!this.hasRevealedPreimage(height, key))
                missing_validators_lower_bound ~= cast(uint)idx;
        }

        // trying to retrieve preimages that - based on the consensus data -
        // was shared with other nodes
        foreach (const validator_ind; setDifference(missing_validators_lower_bound, missing_validators))
            this.enrolls_keys_for_unknown_preimages.put(keys[validator_ind]);

        // NodeA will check the candidate from NodeB in the following way:
        //
        // Current missing validators in NodeA(=sorted_missing_validators_lower_bound) ⊆
        // missing validators in the candidate from NodeB(=sorted_missing_validators) ⊆
        // missing validators in NodeA before the nomination round started
        // (=sorted_missing_validators_higher_bound)
        //
        // If both of those conditions true, then NodeA will accept the candidate.

        auto sorted_missing_validators = missing_validators.dup().sort();
        auto sorted_missing_validators_lower_bound = missing_validators_lower_bound.dup().sort();
        auto sorted_missing_validators_higher_bound = missing_validators_higher_bound.dup().sort();

        if (!setDifference(sorted_missing_validators_lower_bound, sorted_missing_validators).empty())
            return "Lower bound violation - Missing validator mismatch " ~
                assumeWontThrow(to!string(sorted_missing_validators_lower_bound)) ~
                " is not a subset of " ~ assumeWontThrow(to!string(sorted_missing_validators));

        if (!setDifference(sorted_missing_validators, sorted_missing_validators_higher_bound).empty())
            return "Higher bound violation - Missing validator mismatch " ~
                assumeWontThrow(to!string(sorted_missing_validators)) ~
                " is not a subset of " ~ assumeWontThrow(to!string(sorted_missing_validators_higher_bound));

        return null;
    }

    /// return the last payment block before the current block
    public Height getLastPaymentBlock () const scope @safe @nogc nothrow pure
    {
        return lastPaymentBlock(this.getBlockHeight, this.params.PayoutPeriod);
    }

    version (unittest):

    /// Make sure the preimages are available when the block is validated
    private void simulatePreimages (in Height height, uint[] skip_indexes = null) @safe nothrow
    {
        try
        {
            auto validators = this.getValidators(height);

            void addPreimages (in PublicKey public_key, in PreImageInfo preimage_info)
            {
                log.info("Adding test preimages for height {} for validator {}: {}", height, public_key, preimage_info);
                this.enroll_man.addPreimages([ preimage_info ]);
            }
            validators.enumerate.each!((idx, val)
            {
                if (skip_indexes.length && skip_indexes.canFind(idx))
                    log.info("Skip add preimage for validator idx {} at height {} as requested by test", idx, height);
                else
                    addPreimages(val.address, PreImageInfo(val.preimage.utxo,
                        getWellKnownPreimages(WK.Keys[val.address])[height], height));
            });
        } catch (Exception e)
        {
            log.error("simulatePreimages: height: {} exception thrown: {}", height, e);
        }
    }
}

private Height lastPaymentBlock(in Height height, uint payout_period) @safe @nogc nothrow pure
{
    return Height(height <= payout_period ? 1 : (height - 1) - ((height - 1) % payout_period));
}

// expected is the height of last payment block not including current if it is one
unittest
{
    import std.range;
    import std.typecons;

    const uint paymentPeriod = 5;
    only(tuple(0,1), tuple(1,1), tuple(4,1), tuple(5,1), // test before first reward block is externalized
        tuple(6,5), tuple(9,5), tuple(10,5), // test before second reward block is externalized
        tuple(11,10)).each!( // last we test after second
        (height, expected) => assert(lastPaymentBlock(Height(height), paymentPeriod) == expected));
}

/*******************************************************************************

    A ledger that participate in the consensus protocol

    This ledger is held by validators, as they need to do additional bookkeeping
    when e.g. proposing transactions.

*******************************************************************************/

public class ValidatingLedger : Ledger
{
    /// See parent class
    public this (immutable(ConsensusParams) params,
        Engine engine, UTXOSet utxo_set, IBlockStorage storage,
        EnrollmentManager enroll_man, TransactionPool pool,
        FeeManager fee_man, Clock clock,
        Duration block_timestamp_tolerance,
        void delegate (in Block, bool) @safe onAcceptedBlock)
    {
        super(params, engine, utxo_set, storage, enroll_man, pool, fee_man,
            clock, block_timestamp_tolerance, onAcceptedBlock);
    }

    /***************************************************************************

        Collect up to a maximum number of transactions to nominate

        Params:
            txs = will contain the transaction set to nominate,
                  or empty if not enough txs were found
            max_txs = the maximum number of transactions to prepare.

    ***************************************************************************/

    public void prepareNominatingSet (out ConsensusData data, ulong max_txs,
            TimePoint nomination_start_time)
        @safe
    {
        if (clock.networkTime < this.params.GenesisTimestamp)
        {
            log.error("Network time [{}] is before Genesis timestamp [{}]. Will not nominate yet.",
                clock.networkTime, this.params.GenesisTimestamp);
            return;
        }
        const genesis_offset =  nomination_start_time - this.params.GenesisTimestamp;
        data.time_offset = max(genesis_offset, this.last_block.header.time_offset + 1);
        log.trace("Going to nominate current time offset [{}] or newer. Genesis timestamp is [{}]", data.time_offset, this.params.GenesisTimestamp);
        const next_height = this.getBlockHeight() + 1;

        data.enrolls = this.getCandidateEnrollments(next_height);
        data.missing_validators = this.getCandidateMissingValidators(next_height);
        data.tx_set = this.getCandidateTransactions(next_height, max_txs,
            data.missing_validators);
    }

    /***************************************************************************

        Returns: A list of Enrollments that can be used for the next block

    ***************************************************************************/

    public Enrollment[] getCandidateEnrollments (in Height height) @safe
    {
        return this.enroll_man.getEnrollments(height, &this.utxo_set.peekUTXO);
    }

    /***************************************************************************

        Returns:
            A list of Validators that have not yet revealed their PreImage for
            height `height` (based on the current Ledger's knowledge).

    ***************************************************************************/

    public uint[] getCandidateMissingValidators (in Height height) @safe
    {
        Hash[] keys;
        if (!this.enroll_man.getEnrolledUTXOs(height, keys) || keys.length == 0)
            assert(0, "Could not retrieve enrollments / no enrollments found");

        uint[] result;
        foreach (idx, utxo_key; keys)
            if (!this.hasRevealedPreimage(height, utxo_key))
                result ~= cast(uint)idx;
        return result;
    }

    /***************************************************************************

        Returns:
            A list of Transaction hash that can be included in the next block

    ***************************************************************************/

    public Hash[] getCandidateTransactions (
        in Height height, ulong max_txs, in uint[] missing_validators) @safe
    {
        Hash[] result;
        Amount tot_fee, tot_data_fee;
        auto utxo_finder = this.utxo_set.getUTXOFinder();

        foreach (ref Hash hash, ref Transaction tx; this.pool)
        {
            scope checkAndAcc = (in Transaction tx, Amount sum_unspent) {
                const err = this.fee_man.check(tx, sum_unspent);
                if (!err)
                {
                    tot_fee.add(sum_unspent);
                    tot_data_fee.add(
                        this.fee_man.getDataFee(tx.payload.length));
                }
                return err;
            };

            if (auto reason = tx.isInvalidReason(
                    this.engine, utxo_finder, height, checkAndAcc))
                log.trace("Rejected invalid ('{}') tx: {}", reason, tx);
            else
                result ~= hash;

            if (result.length >= max_txs)
            {
                result.sort();
                return result;
            }
        }

        const pre_cb_len = result.length;
        // Dont append a CB TX to an empty TX set
        if (pre_cb_len > 0)
            result ~= this.getCoinbaseTX(height, tot_fee, tot_data_fee,
                missing_validators).map!(tx => tx.hashFull()).array;
        // No more than 1 CB per block
        assert(result.length - pre_cb_len <= 1);
        return result;
    }

    /***************************************************************************

        Calculate the transaction fee and adjust the fee based on the
        transaction's size measured in bytes.

        The bigger the transaction size is, the smaller the adjusted fee becomes.

        Params:
            tx = transaction for which we want to calculate the adjusted fee
            tot_fee = total adjusted fee

        Returns: string describing the error, if an error happened, null otherwise

    ***************************************************************************/

    public string getAdjustedTXFee (in Transaction tx, out Amount tot_fee) nothrow @safe
    {
        return this.fee_man.getAdjustedTXFee(tx, &this.utxo_set.peekUTXO, tot_fee);
    }

    /***************************************************************************

        Calculate the transaction fee and adjust the fee based on the
        transaction's size measured in bytes.

        The bigger the transaction size is, the smaller the adjusted fee becomes.

        Params:
            tx_hash = tx hash for which we want to calculate the adjusted fee
            tot_fee = total adjusted fee

        Returns: string describing the error, if an error happened, null otherwise

    ***************************************************************************/

    public string getAdjustedTXFee (in Hash tx_hash, out Amount tot_fee) nothrow @safe
    {
        auto tx = this.pool.getTransactionByHash(tx_hash);
        if (tx == Transaction.init)
            return InvalidConsensusDataReason.NotInPool;
        return this.fee_man.getAdjustedTXFee(tx, &this.utxo_set.peekUTXO, tot_fee);
    }

    /***************************************************************************

        Get an UTXO, no double-spend protection.

        Params:
            hash = the hash of the UTXO (`hashMulti(tx_hash, index)`)
            value = the UTXO

        Returns:
            true if the UTXO was found

    ***************************************************************************/

    public bool peekUTXO (in Hash utxo, out UTXO value) nothrow @safe
    {
        return this.utxo_set.peekUTXO(utxo, value);
    }

    version (unittest):

    private bool externalize (ConsensusData data,
        string file = __FILE__, size_t line = __LINE__)
        @trusted
    {
        import agora.utils.Test : WK;

        auto next_block = Height(this.last_block.header.height + 1);
        auto key_pairs = this.getValidators(next_block)
            .map!(vi => WK.Keys[vi.address])
            .array();

        Transaction[] externalized_tx_set;
        if (auto fail_reason = this.getValidTXSet(data, externalized_tx_set))
        {
            log.info("Missing TXs, can not create new block at Height {} : {}",
                next_block, prettify(data));
            return false;
        }
        const block = makeNewTestBlock(this.last_block,
            externalized_tx_set, key_pairs,
            data.enrolls, data.missing_validators, data.time_offset);
        return this.acceptBlock(block, file, line);
    }

    /// simulate block creation as if a nomination and externalize round completed
    private void forceCreateBlock (ulong max_txs = Block.TxsInTestBlock,
        string file = __FILE__, size_t line = __LINE__)
    {
        const next_block = this.getBlockHeight() + 1;
        this.simulatePreimages(next_block);
        ConsensusData data;
        this.prepareNominatingSet(data, max_txs, this.clock.networkTime());
        assert(data.tx_set.length >= max_txs);

        // If the user provided enrollments, do not re-enroll automatically
        // If they didn't, check to see if the next block needs them
        // In which case, we simply re-enroll the validators already enrolled
        if (data.enrolls.length == 0 &&
            this.enroll_man.validator_set.countActive(next_block + 1) == 0)
        {
            auto validators = this.getValidators(this.getBlockHeight());
            foreach (v; validators)
            {
                auto kp = WK.Keys[v.address];
                auto enroll = EnrollmentManager.makeEnrollment(
                    v.utxo, kp, next_block, this.params.ValidatorCycle);

                data.enrolls ~= enroll;
            }
        }

        const expected_ts = this.params.GenesisTimestamp + data.time_offset;
        if (this.clock.networkTime() < expected_ts ||
            this.clock.networkTime() > (expected_ts + block_time_offset_tolerance.total!"seconds"))
        {
            if (auto mc = cast(MockClock) this.clock)
                mc.setTime(this.params.GenesisTimestamp + data.time_offset);
            else
                assert(0, "Need a MockClock or time handled correctly to call forceCreateBlock");
        }
        if (!this.externalize(data, file, line))
        {
            assert(0, format!"Failure in unit test. Block %s should have been externalized!"(
                       this.getBlockHeight() + 1));
        }
    }

    /// Generate a new block by creating transactions, then calling `forceCreateBlock`
    private Transaction[] makeTestBlock (
        Transaction[] last_txs, ulong txs = Block.TxsInTestBlock,
        string file = __FILE__, size_t line = __LINE__)
    {
        assert(txs > 0);

        // Special case for genesis
        if (!last_txs.length)
        {
            assert(this.getBlockHeight() == 0);

            last_txs = genesisSpendable().take(Block.TxsInTestBlock).enumerate()
                .map!(en => en.value.refund(WK.Keys.A.address).sign())
                .array();
            last_txs.each!(tx => this.acceptTransaction(tx));
            this.forceCreateBlock(txs, file, line);
            return last_txs;
        }

        last_txs = last_txs.map!(tx => TxBuilder(tx).sign()).array();
        last_txs.each!(tx => assert(this.acceptTransaction(tx)));
        this.forceCreateBlock(txs, file, line);
        return last_txs;
    }
}

/// Note: these unittests historically assume a block always contains
/// 8 transactions - hence the use of `TxsInTestBlock` appearing everywhere.
version (unittest)
{
    import agora.consensus.validation.Block: getWellKnownPreimages;
    import core.stdc.time : time;

    /// A `Ledger` with sensible defaults for `unittest` blocks
    private final class TestLedger : ValidatingLedger
    {
        public this (KeyPair key_pair,
            const(Block)[] blocks = null,
            immutable(ConsensusParams) params_ = null,
            Duration block_time_offset_tolerance_dur = 600.seconds,
            Clock mock_clock = null)
        {
            const params = (params_ !is null)
                ? params_
                : (blocks.length > 0
                   // Use the provided Genesis block
                   ? new immutable(ConsensusParams)(
                       cast(immutable)blocks[0], WK.Keys.CommonsBudget.address,
                       ConsensusConfig(ConsensusConfig.init.genesis_timestamp,
                                       blocks[0].header.enrollments[0].cycle_length))
                   // Use the unittest genesis block
                   : new immutable(ConsensusParams)());

            // We assume the caller wants to create new blocks, so let's make
            // the clock exactly at the right time. If the caller needs to
            // create many blocks, they'll need to adjust the clock first.
            if (mock_clock is null)
                mock_clock = new MockClock(
                    params.GenesisTimestamp +
                    (blocks.length * params.BlockInterval.total!"seconds"));

            auto stateDB = new ManagedDatabase(":memory:");
            auto cacheDB = new ManagedDatabase(":memory:");
            super(params,
                new Engine(TestStackMaxTotalSize, TestStackMaxItemSize),
                new UTXOSet(stateDB),
                new MemBlockStorage(blocks),
                new EnrollmentManager(stateDB, cacheDB, key_pair, params),
                new TransactionPool(cacheDB),
                new FeeManager(stateDB, params),
                mock_clock,
                block_time_offset_tolerance_dur, null);
        }

        ///
        protected override void replayStoredBlock (in Block block) @safe
        {
            if (block.header.height > 0)
                this.simulatePreimages(block.header.height);
            super.replayStoredBlock(block);
        }
    }

    // sensible defaults
    private const TestStackMaxTotalSize = 16_384;
    private const TestStackMaxItemSize = 512;
}

///
unittest
{
    scope ledger = new TestLedger(WK.Keys.NODE3);
    assert(ledger.getBlockHeight() == 0);

    auto blocks = ledger.getBlocksFrom(Height(0)).take(10);
    assert(blocks[$ - 1] == ledger.params.Genesis);

    Transaction[] last_txs;
    void genBlockTransactions (size_t count)
    {
        foreach (_; 0 .. count)
            last_txs = ledger.makeTestBlock(last_txs);
    }

    genBlockTransactions(2);
    blocks = ledger.getBlocksFrom(Height(0)).take(10);
    assert(blocks[0] == ledger.params.Genesis);
    assert(blocks.length == 3);  // two blocks + genesis block

    /// now generate 98 more blocks to make it 100 + genesis block (101 total)
    genBlockTransactions(98);
    assert(ledger.getBlockHeight() == 100);

    blocks = ledger.getBlocksFrom(Height(0)).takeExactly(10);
    assert(blocks[0] == ledger.params.Genesis);
    assert(blocks.length == 10);

    /// lower limit
    blocks = ledger.getBlocksFrom(Height(0)).takeExactly(5);
    assert(blocks[0] == ledger.params.Genesis);
    assert(blocks.length == 5);

    /// different indices
    blocks = ledger.getBlocksFrom(Height(1)).takeExactly(10);
    assert(blocks[0].header.height == 1);
    assert(blocks.length == 10);

    blocks = ledger.getBlocksFrom(Height(50)).takeExactly(10);
    assert(blocks[0].header.height == 50);
    assert(blocks.length == 10);

    blocks = ledger.getBlocksFrom(Height(95)).take(10);  // only 6 left from here (block 100 included)
    assert(blocks.front.header.height == 95);
    assert(blocks.walkLength() == 6);

    blocks = ledger.getBlocksFrom(Height(99)).take(10);  // only 2 left from here (ditto)
    assert(blocks.front.header.height == 99);
    assert(blocks.walkLength() == 2);

    blocks = ledger.getBlocksFrom(Height(100)).take(10);  // only 1 block available
    assert(blocks.front.header.height == 100);
    assert(blocks.walkLength() == 1);

    // over the limit => return up to the highest block
    assert(ledger.getBlocksFrom(Height(0)).take(1000).walkLength() == 101);

    // higher index than available => return nothing
    assert(ledger.getBlocksFrom(Height(1000)).take(10).walkLength() == 0);
}

/// basic block verification
unittest
{
    scope ledger = new TestLedger(genesis_validator_keys[0]);

    Block invalid_block;  // default-initialized should be invalid
    assert(!ledger.acceptBlock(invalid_block));

    auto txs = genesisSpendable().map!(txb => txb.sign()).array();
    const block = makeNewTestBlock(ledger.params.Genesis, txs);
    ledger.simulatePreimages(ledger.getBlockHeight() + 1);
    assert(ledger.acceptBlock(block));
}

/// Situation: Ledger is constructed with blocks present in storage
/// Expectation: The UTXOSet is populated with all up-to-date UTXOs
unittest
{
    import agora.consensus.data.genesis.Test;

    const(Block)[] blocks = [
        GenesisBlock,
        makeNewTestBlock(GenesisBlock, GenesisBlock.spendable().map!(txb => txb.sign()))
    ];
    // Make 3 more blocks to put in storage
    foreach (idx; 2 .. 5)
    {
        blocks ~= makeNewTestBlock(
            blocks[$ - 1],
            blocks[$ - 1].spendable().map!(txb => txb.sign()));
    }

    // And provide it to the ledger
    scope ledger = new TestLedger(genesis_validator_keys[0], blocks);

    assert(ledger.utxo_set.length
           == /* Genesis, Frozen */ 6 + 8 /* Block #1 Payments*/);

    // Ensure that all previously-generated outputs are in the UTXO set
    {
        auto findUTXO = ledger.utxo_set.getUTXOFinder();
        UTXO utxo;
        assert(
            blocks[$ - 1].txs.all!(
                tx => iota(tx.outputs.length).all!(
                    (idx) {
                        return findUTXO(UTXO.getHash(tx.hashFull(), idx), utxo) &&
                            utxo.output == tx.outputs[idx];
                    }
                )
            )
        );
    }
}

unittest
{
    import agora.consensus.data.genesis.Test;
    ConsensusData data;
    MockClock mock_clock = new MockClock(time(null));

    auto getLedger (Clock clock)
    {
        auto ledger = new TestLedger(genesis_validator_keys[0], null, new immutable(ConsensusParams)(20, 7, 80), 600.seconds, clock);
        auto txs = genesisSpendable().enumerate()
            .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
            .array();
        txs.each!(tx => assert(ledger.acceptTransaction(tx)));
        ledger.simulatePreimages(ledger.getBlockHeight() + 1);
        return ledger;
    }

    // no matter how far the clock is ahead, we still accept blocks as long as
    // the clock has a time greater than the time in the latest block header
    auto ledger = getLedger(mock_clock);
    ledger.prepareNominatingSet(data, Block.TxsInTestBlock, mock_clock.networkTime());
    data.time_offset = 1;
    mock_clock.setTime(ledger.params.GenesisTimestamp + 2000);
    assert(ledger.externalize(data));

    // if the clock is behind of the time_offset of the new block and
    // ahead of the time_offset of the last block and
    // and within the tolerance interval,
    // then we accept block
    ledger = getLedger(mock_clock);
    data.time_offset = 1000;
    mock_clock.setTime(ledger.params.GenesisTimestamp + 500);
    assert(ledger.externalize(data));

    // if the clock is behind of the time_offset of the new block and
    // ahead of the time_offset of the last block and
    // and NOT within the tolerance interval,
    // then we reject block
    ledger = getLedger(mock_clock);
    data.time_offset = 1000;
    mock_clock.setTime(ledger.params.GenesisTimestamp + 100);
    assert(!ledger.externalize(data));
    // if the time passes by and now we are within the tolerance interval, then
    // we will accept block
    mock_clock.setTime(ledger.params.GenesisTimestamp + 900);
    assert(ledger.externalize(data));

    // if the clock is behind of the time_offset of the latest accepted block, then
    // we reject the block regardless of the current time
    ledger = getLedger(mock_clock);
    data.time_offset = -1;
    mock_clock.setTime(ledger.params.GenesisTimestamp + 100);
    assert(!ledger.externalize(data));
}

// Return Genesis block plus 'count' number of blocks
version (unittest)
private immutable(Block)[] genBlocksToIndex (
    size_t count, scope immutable(ConsensusParams) params)
{
    const(Block)[] blocks = [ params.Genesis ];
    scope ledger = new TestLedger(genesis_validator_keys[0]);
    foreach (_; 0 .. count)
    {
        auto txs = blocks[$ - 1].spendable().map!(txb => txb.sign());
        auto cycle = blocks[$ - 1].header.height / params.ValidatorCycle;
        blocks ~= makeNewTestBlock(blocks[$ - 1], txs);
    }
    if (blocks)
    {
        ledger.simulatePreimages(blocks[$ - 1].header.height);
    }
    return blocks.assumeUnique;
}

/// test enrollments in the genesis block
unittest
{
    // Default test genesis block has 6 validators
    {
        scope ledger = new TestLedger(WK.Keys.A);
        assert(ledger.getValidators(Height(1)).length == 6);
    }

    // One block before `ValidatorCycle`, validator is still active
    {
        const ValidatorCycle = 20;
        auto params = new immutable(ConsensusParams)(ValidatorCycle);
        const blocks = genBlocksToIndex(ValidatorCycle - 1, params);
        scope ledger = new TestLedger(WK.Keys.A, blocks, params);
        Hash[] keys;
        assert(ledger.getValidators(Height(ValidatorCycle)).length == 6);
    }

    // Past `ValidatorCycle`, validator is inactive
    {
        const ValidatorCycle = 20;
        auto params = new immutable(ConsensusParams)(ValidatorCycle);
        const blocks = genBlocksToIndex(ValidatorCycle, params);
        // Enrollment: Insufficient number of active validators
        assertThrown!Exception(new TestLedger(WK.Keys.A, blocks, params));
    }
}

/// test atomicity of adding blocks and rolling back
unittest
{
    import std.conv;
    import core.stdc.time : time;

    static class ThrowingLedger : Ledger
    {
        bool throw_in_update_utxo;
        bool throw_in_update_validators;

        public this (KeyPair kp, const(Block)[] blocks, immutable(ConsensusParams) params)
        {
            auto stateDB = new ManagedDatabase(":memory:");
            auto cacheDB = new ManagedDatabase(":memory:");
            super(params, new Engine(TestStackMaxTotalSize, TestStackMaxItemSize),
                new UTXOSet(stateDB),
                new MemBlockStorage(blocks),
                new EnrollmentManager(stateDB, cacheDB, kp, params),
                new TransactionPool(cacheDB),
                new FeeManager(),
                new MockClock(params.GenesisTimestamp +
                              (blocks.length * params.BlockInterval.total!"seconds")));
        }

        ///
        protected override void replayStoredBlock (in Block block) @safe
        {
            if (block.header.height > 0)
                this.simulatePreimages(block.header.height);
            super.replayStoredBlock(block);
        }

        override void updateUTXOSet (in Block block) @safe
        {
            super.updateUTXOSet(block);
            if (this.throw_in_update_utxo)
                throw new Exception("");
        }

        override void updateValidatorSet (in Block block) @safe
        {
            super.updateValidatorSet(block);
            if (this.throw_in_update_validators)
                throw new Exception("");
        }
    }

    const params = new immutable(ConsensusParams)();

    // throws in updateUTXOSet() => rollback() called, UTXO set reverted,
    // Validator set was not modified
    {
        const blocks = genBlocksToIndex(params.ValidatorCycle, params);
        assert(blocks.length == params.ValidatorCycle + 1);  // +1 for genesis

        scope ledger = new ThrowingLedger(
            WK.Keys.A, blocks.takeExactly(params.ValidatorCycle), params);
        assert(ledger.getValidators(Height(params.ValidatorCycle)).length == 6);
        auto utxos = ledger.utxo_set.getUTXOs(WK.Keys.Genesis.address);
        assert(utxos.length == 8);
        utxos.each!(utxo => assert(utxo.unlock_height == params.ValidatorCycle));

        ledger.throw_in_update_utxo = true;
        auto next_block = blocks[$ - 1];
        assertThrown!Exception(ledger.addValidatedBlock(next_block));
        assert(ledger.last_block == blocks[$ - 2]);  // not updated
        utxos = ledger.utxo_set.getUTXOs(WK.Keys.Genesis.address);
        assert(utxos.length == 8);
        utxos.each!(utxo => assert(utxo.unlock_height == params.ValidatorCycle));  // reverted
        // not updated
        assert(ledger.getValidators(Height(params.ValidatorCycle)).length == 6);
    }

    // throws in updateValidatorSet() => rollback() called, UTXO set and
    // Validator set reverted
    {
        const blocks = genBlocksToIndex(params.ValidatorCycle, params);
        assert(blocks.length == 21);  // +1 for genesis

        scope ledger = new ThrowingLedger(
            WK.Keys.A, blocks.takeExactly(params.ValidatorCycle), params);
        assert(ledger.getValidators(Height(params.ValidatorCycle)).length == 6);
        auto utxos = ledger.utxo_set.getUTXOs(WK.Keys.Genesis.address);
        assert(utxos.length == 8);
        utxos.each!(utxo => assert(utxo.unlock_height == params.ValidatorCycle));

        ledger.throw_in_update_validators = true;
        auto next_block = blocks[$ - 1];
        assertThrown!Exception(ledger.addValidatedBlock(next_block));
        assert(ledger.last_block == blocks[$ - 2]);  // not updated
        utxos = ledger.utxo_set.getUTXOs(WK.Keys.Genesis.address);
        assert(utxos.length == 8);
        utxos.each!(utxo => assert(utxo.unlock_height == params.ValidatorCycle));  // reverted
        assert(ledger.getValidators(ledger.last_block.header.height).length == 6);
    }
}

/// throw if the gen block in block storage is different to the configured one
unittest
{
    import agora.consensus.data.genesis.Test;
    import agora.consensus.data.genesis.Coinnet : CoinGenesis = GenesisBlock;

    // ConsensusParams is instantiated by default with the test genesis block
    immutable params = new immutable(ConsensusParams)(CoinGenesis, WK.Keys.CommonsBudget.address);

    try
    {
        scope ledger = new TestLedger(WK.Keys.A, [GenesisBlock], params);
        assert(0);
    }
    catch (Exception ex)
    {
        assert(ex.msg == "Genesis block loaded from disk is different from the one in the config file");
    }

    immutable good_params = new immutable(ConsensusParams)();
    // will not fail
    scope ledger = new TestLedger(WK.Keys.A, [GenesisBlock], good_params);
    // Neither will the default
    scope other_ledger = new TestLedger(WK.Keys.A, [GenesisBlock]);
}

unittest
{
    scope ledger = new TestLedger(genesis_validator_keys[0]);
    scope fee_man = new FeeManager();

    // Generate payment transactions to the first 8 well-known keypairs
    auto txs = genesisSpendable().enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array;
    txs.each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();
    assert(ledger.getBlockHeight() == 1);

    // Create data with nomal size
    ubyte[] data;
    data.length = 64;
    foreach (idx; 0 .. data.length)
        data[idx] = cast(ubyte)(idx % 256);

    // Calculate fee
    Amount data_fee = fee_man.getDataFee(data.length);

    // Generate a block with data stored transactions
    txs = txs.enumerate()
        .map!(en => TxBuilder(en.value)
              .deduct(data_fee)
              .payload(data)
              .sign())
              .array;
    txs.each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();
    assert(ledger.getBlockHeight() == 2);
    auto blocks = ledger.getBlocksFrom(Height(0)).take(10).array;
    assert(blocks.length == 3);
    assert(blocks[2].header.height == 2);

    auto not_coinbase_txs = blocks[2].txs.filter!(tx => tx.isPayment).array;
    foreach (ref tx; not_coinbase_txs)
    {
        assert(tx.outputs.any!(o => o.type != OutputType.Coinbase));
        assert(tx.outputs.length > 0);
        assert(tx.payload == data);
    }

    // Generate a block to reuse transactions used for data storage
    txs = txs.enumerate()
        .map!(en => TxBuilder(en.value)
              .refund(WK.Keys[Block.TxsInTestBlock + en.index].address)
              .sign())
              .array;
    txs.each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();
    assert(ledger.getBlockHeight() == 3);
    blocks = ledger.getBlocksFrom(Height(0)).take(10).array;
    assert(blocks.length == 4);
    assert(blocks[3].header.height == 3);
}

// create slashing data and check validity for that
unittest
{
    import agora.consensus.data.genesis.Test;
    import agora.consensus.PreImage;

    auto params = new immutable(ConsensusParams)(20);
    const(Block)[] blocks = [ GenesisBlock ];
    auto mock_clock = new MockClock(params.GenesisTimestamp + 1);
    scope ledger = new TestLedger(genesis_validator_keys[0], blocks, params, 600.seconds, mock_clock);

    Transaction[] genTransactions (Transaction[] txs)
    {
        return txs.enumerate()
            .map!(en => TxBuilder(en.value).refund(WK.Keys[en.index].address)
                .sign())
            .array;
    }

    Transaction[] genGeneralBlock (Transaction[] txs,
        string file = __FILE__, size_t line = __LINE__)
    {
        auto new_txs = genTransactions(txs);
        new_txs.each!(tx => assert(ledger.acceptTransaction(tx)));
        ledger.forceCreateBlock(Block.TxsInTestBlock, file, line);
        return new_txs;
    }

    // generate payment transaction to the first 8 well-known keypairs
    auto genesis_txs = genesisSpendable().array;
    auto txs = genesis_txs[0 .. 4].enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign()).array;
    txs ~= genesis_txs[4 .. 8].enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign()).array;
    txs.each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();
    assert(ledger.getBlockHeight() == 1);

    // generate a block with only freezing transactions
    auto new_txs = txs[0 .. 4].enumerate()
        .map!(en => TxBuilder(en.value).refund(WK.Keys[en.index].address)
            .sign(OutputType.Freeze)).array;
    new_txs ~= txs[4 .. 7].enumerate()
        .map!(en => TxBuilder(en.value).refund(WK.Keys[en.index].address).sign())
        .array;
    new_txs ~= TxBuilder(txs[$ - 1]).split(WK.Keys[0].address.repeat(8)).sign();
    new_txs.each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();
    assert(ledger.getBlockHeight() == 2);

    // UTXOs for enrollments
    Hash[] utxos = [
        UTXO.getHash(hashFull(new_txs[0]), 0),
        UTXO.getHash(hashFull(new_txs[1]), 0),
        UTXO.getHash(hashFull(new_txs[2]), 0),
        UTXO.getHash(hashFull(new_txs[3]), 0)
    ];

    new_txs = iota(new_txs[$ - 1].outputs.length).enumerate
        .map!(en => TxBuilder(new_txs[$ - 1], cast(uint)en.index)
            .refund(WK.Keys[en.index].address).sign())
        .array;
    new_txs.each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();
    assert(ledger.getBlockHeight() == 3);

    foreach (height; 4 .. params.ValidatorCycle)
    {
        new_txs = genGeneralBlock(new_txs);
        assert(ledger.getBlockHeight() == Height(height));
    }

    // add four new enrollments
    Enrollment[] enrollments;
    PreImageCycle[] cycles;
    auto pairs = iota(4).map!(idx => WK.Keys[idx]).array;
    foreach (idx, kp; pairs)
    {
        auto cycle = PreImageCycle(kp.secret, params.ValidatorCycle);
        const seed = cycle[Height(params.ValidatorCycle)];
        cycles ~= cycle;
        auto enroll = EnrollmentManager.makeEnrollment(
            utxos[idx], kp, seed, params.ValidatorCycle);
        assert(ledger.enroll_man.addEnrollment(enroll, kp.address,
            Height(params.ValidatorCycle), &ledger.utxo_set.peekUTXO));
        enrollments ~= enroll;
    }

    foreach (idx, hash; utxos)
    {
        Enrollment stored_enroll = ledger.enroll_man.getEnrollment(hash);
        assert(stored_enroll == enrollments[idx]);
    }

    // create the last block of the cycle to make the `Enrollment`s enrolled
    new_txs = genGeneralBlock(new_txs);
    assert(ledger.getBlockHeight() == Height(20));
    auto b20 = ledger.getBlocksFrom(Height(20))[0];
    assert(b20.header.enrollments.length == 4);

    // block 21
    new_txs = genGeneralBlock(new_txs);
    assert(ledger.getBlockHeight() == Height(21));

    // check missing validators not revealing pre-images.
    auto temp_txs = genTransactions(new_txs);
    temp_txs.each!(tx => assert(ledger.acceptTransaction(tx)));

    // Add preimages for validators at height 22 but skip for a couple
    uint[] skip_indexes = [ 1, 3 ];
    ledger.simulatePreimages(Height(22), skip_indexes);

    ConsensusData data;
    ledger.prepareNominatingSet(data, Block.TxsInTestBlock, mock_clock.networkTime());
    assert(data.missing_validators.length == 2);
    assert(data.missing_validators == skip_indexes);

    // check validity of slashing information
    assert(ledger.validateSlashingData(Height(22), data, skip_indexes) == null);
    ConsensusData forged_data = data;
    forged_data.missing_validators = [3, 2, 1];
    assert(ledger.validateSlashingData(Height(22), forged_data, skip_indexes) != null);

    // Now reveal for all active validators at height 22
    ledger.simulatePreimages(Height(22));

    // there's no missing validator at the height of 22
    // after revealing preimages
    temp_txs.each!(tx => ledger.pool.remove(tx));
    temp_txs = genTransactions(new_txs);
    temp_txs.each!(tx => assert(ledger.acceptTransaction(tx)));

    ledger.prepareNominatingSet(data, Block.TxsInTestBlock, mock_clock.networkTime());
    assert(data.missing_validators.length == 0);
}

unittest
{
    import agora.consensus.data.genesis.Test;
    import agora.consensus.PreImage;
    import agora.utils.WellKnownKeys : CommonsBudget;

    ConsensusConfig config = { validator_cycle: 20, payout_period: 5 };
    auto params = new immutable(ConsensusParams)(GenesisBlock,
        CommonsBudget.address, config);

    const(Block)[] blocks = [ GenesisBlock ];
    auto mock_clock = new MockClock(params.GenesisTimestamp + 1);
    scope ledger = new TestLedger(genesis_validator_keys[0], blocks, params, 600.seconds, mock_clock);

    // Add preimages for all validators (except for two of them) till end of cycle
    uint[] skip_indexes = [ 2, 5 ];

    ledger.simulatePreimages(Height(params.ValidatorCycle), skip_indexes);

    // Block with no fee
    auto no_fee_txs = blocks[$-1].spendable.map!(txb => txb.sign()).array();
    no_fee_txs.each!(tx => assert(ledger.acceptTransaction(tx)));

    ConsensusData data;
    ledger.prepareNominatingSet(data, Block.TxsInTestBlock, mock_clock.networkTime());

    assert(ledger.validateConsensusData(data, skip_indexes) is null);

    data.missing_validators = [2,5,7];
    assert(ledger.validateConsensusData(data, [2,3,5,7,9]) is null);

    data.missing_validators = [2,5];
    assert(ledger.validateConsensusData(data, [2]) == "Higher bound violation - Missing validator mismatch [2, 5] is not a subset of [2]");

    data.missing_validators = [5];
    assert(ledger.validateConsensusData(data, [2]) == "Lower bound violation - Missing validator mismatch [2, 5] is not a subset of [5]");
}

unittest
{
    import agora.consensus.data.genesis.Test;
    import agora.consensus.PreImage;
    import agora.utils.WellKnownKeys : CommonsBudget;

    ConsensusConfig config = { validator_cycle: 20, payout_period: 5 };
    auto params = new immutable(ConsensusParams)(GenesisBlock,
        CommonsBudget.address, config);

    const(Block)[] blocks = [ GenesisBlock ];
    auto mock_clock = new MockClock(params.GenesisTimestamp + 1);
    scope ledger = new TestLedger(genesis_validator_keys[0], blocks, params, 600.seconds, mock_clock);

    // Add preimages for all validators (except for two of them) till end of cycle
    uint[] skip_indexes = [ 2, 5 ];

    auto validators = ledger.getValidators(Height(1));
    UTXO[] mpv_stakes;
    foreach (skip; skip_indexes)
        assert(ledger.utxo_set.peekUTXO(validators[skip].utxo, mpv_stakes[(++mpv_stakes.length) - 1]));

    ledger.simulatePreimages(Height(params.ValidatorCycle), skip_indexes);

    // Block with no fee
    auto no_fee_txs = blocks[$-1].spendable.map!(txb => txb.sign()).array();
    no_fee_txs.each!(tx => assert(ledger.acceptTransaction(tx)));

    ConsensusData data;
    ledger.prepareNominatingSet(data, Block.TxsInTestBlock, mock_clock.networkTime());
    // This is a block with no fees, a ConsensusData with Coinbase TXs should
    // fail validation. But since the Ledger does not know about the hash, it will
    // think someone else may validate it.
    data.tx_set ~= Transaction([Input(Height(blocks.length))],
        [Output(Amount(1), CommonsBudgetAddress, OutputType.Coinbase)]).hashFull();
    assert(ledger.validateConsensusData(data, skip_indexes) ==
        Ledger.InvalidConsensusDataReason.MayBeValid);

    ledger.prepareNominatingSet(data, Block.TxsInTestBlock, mock_clock.networkTime());
    ledger.externalize(data);
    assert(ledger.getBlockHeight() == blocks.length);
    blocks ~= ledger.getBlocksFrom(Height(blocks.length))[0];

    // No Coinbase TX
    assert(blocks[$-1].txs.filter!(tx => tx.isCoinbase).array.length == 0);

    // Create blocks from height 2 to 6, with fees
    foreach (height; 2..7)
    {
        Amount per_tx_fee = Amount.UnitPerCoin;
        auto txs = blocks[$-1].spendable.map!(txb =>
            txb.deduct(per_tx_fee).sign()).array();
        txs.each!(tx => assert(ledger.acceptTransaction(tx)));

        data = ConsensusData.init;
        ledger.prepareNominatingSet(data, Block.TxsInTestBlock, mock_clock.networkTime());

        // Remove the coinbase TX
        data.tx_set = data.tx_set[0 .. $ - 1];
        assert(ledger.validateConsensusData(data, skip_indexes) == "Invalid Coinbase transaction");
        // Add Invalid coinbase TX
        data.tx_set ~= Transaction([
            Output(Amount(1), CommonsBudgetAddress, OutputType.Coinbase),
            Output(Amount(1), CommonsBudgetAddress, OutputType.Payment)]).hashFull();
        assert(ledger.validateConsensusData(data, skip_indexes) == "Invalid Coinbase transaction");

        ledger.prepareNominatingSet(data, Block.TxsInTestBlock, mock_clock.networkTime());
        ledger.externalize(data);
        assert(ledger.getBlockHeight() == blocks.length);
        blocks ~= ledger.getBlocksFrom(Height(blocks.length))[0];

        auto cb_txs = blocks[$-1].txs.filter!(tx => tx.isCoinbase).array;
        assert(cb_txs.length == 1);
        // Payout block should pay the CommonsBudget + all validators (excl MPV)
        // other blocks should only pay CommonsBudget
        if (blocks[$-1].header.height == params.PayoutPeriod)
            assert(cb_txs[0].outputs.length == 1 + genesis_validator_keys.length - skip_indexes.length);
        else
            assert(cb_txs[0].outputs.length == 1);

        // MPV should never be paid
        mpv_stakes.each!((mpv_stake)
        {
            assert(cb_txs[0].outputs.filter!(output => output.address ==
                mpv_stake.output.address).array.length == 0);
        });
    }
}

// Coinbase only ConsensusData and blocks should not be validated
unittest
{
    import agora.utils.WellKnownKeys : CommonsBudget;
    import agora.consensus.data.genesis.Test;

    ConsensusConfig config = { validator_cycle: 20, payout_period: 1 };
    auto params = new immutable(ConsensusParams)(GenesisBlock,
        CommonsBudget.address, config);

    const(Block)[] blocks = [ GenesisBlock ];
    auto mock_clock = new MockClock(params.GenesisTimestamp + 1);
    scope ledger = new TestLedger(genesis_validator_keys[0], blocks, params, 600.seconds, mock_clock);

    auto txs = blocks[$-1].spendable.map!(txb =>
        txb.deduct(Amount.UnitPerCoin).sign()).array();
    assert(ledger.acceptTransaction(txs[0]));
    ledger.forceCreateBlock(1);

    ConsensusData data;
    ledger.prepareNominatingSet(data, 1, mock_clock.networkTime());
    // Coinbase TX should not be nominated.
    assert(data.tx_set.length == 0);

    const Transaction[] empty_tx_set;
    const uint[] empty_mpvs;

    auto cb_tx_set = ledger.getCoinbaseTX(empty_tx_set, empty_mpvs);
    data.tx_set ~= cb_tx_set.map!(tx => tx.hashFull()).array;
    assert(data.tx_set.length == 1);
    // Coinbase only nomination, Should not validate
    assert(ledger.validateConsensusData(data, []) ==
        Ledger.InvalidConsensusDataReason.OnlyCoinbaseTX);
    assert(!ledger.externalize(data));

    auto last_block = ledger.getLastBlock();
    const block = makeNewTestBlock(last_block, cb_tx_set);
    ledger.simulatePreimages(block.header.height);
    assert(ledger.validateBlock(block) == "Block: Must contain other transactions than Coinbase");
}
