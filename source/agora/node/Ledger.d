/*******************************************************************************

    The `Ledger` class binds together other components to provide a consistent
    view of the state of the node.

    The Ledger acts as a bridge between other components, e.g. the `UTXOSet`,
    `EnrollmentManager`, `IBlockStorage`, etc...
    While the `Node` is the main object in Agora, the `Ledger` is the second
    most important class, handling all business logic, relying on the the `Node`
    for anything related to network communicatiion.

    Copyright:
        Copyright (c) 2019-2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.node.Ledger;

import agora.common.Amount;
import agora.common.BitField;
import agora.common.Config;
import agora.common.crypto.Key;
import agora.common.Hash;
import agora.common.ManagedDatabase;
import agora.common.Serializer;
import agora.common.Set;
import agora.common.TransactionPool;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.protocol.Data;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Params;
import agora.consensus.data.Transaction;
import agora.consensus.state.UTXODB;
import agora.consensus.EnrollmentManager;
import agora.consensus.SlashPolicy;
import agora.consensus.validation;
import agora.node.BlockStorage;
import agora.node.Fee;
import agora.stats.Block;
import agora.stats.Tx;
import agora.stats.Utils;
import agora.utils.Log;
import agora.utils.PrettyPrinter;

import std.algorithm;
import std.conv : to;
import std.exception;
import std.format;
import std.range;

mixin AddLogger!();

version (unittest)
{
    //import agora.consensus.data.genesis.Test;
    import agora.utils.Test;
}

/// Ditto
public class Ledger
{
    /// data storage for all the blocks
    private IBlockStorage storage;

    /// Pool of transactions to pick from when generating blocks
    private TransactionPool pool;

    /// The last block in the ledger
    private Block last_block;

    /// UTXO set
    private UTXOSet utxo_set;

    /// Enrollment manager
    private EnrollmentManager enroll_man;

    /// Slashing policy manager
    private SlashPolicy slash_man;

    /// If not null call this delegate
    /// A block was externalized
    private void delegate (const ref Block, bool) @safe onAcceptedBlock;

    /// Parameters for consensus-critical constants
    private immutable(ConsensusParams) params;

    /// Transaction stats
    private TxStats tx_stats;

    /// Block stats
    private BlockStats block_stats;

    /// The checker of transaction data payload
    private DataPayloadChecker payload_checker;

    /***************************************************************************

        Constructor

        Params:
            params = the consensus-critical constants
            utxo_set = the set of unspent outputs
            storage = the block storage
            enroll_man = the enrollmentManager
            pool = the transaction pool
            payload_checker = the checker of data payload
            onAcceptedBlock = optional delegate to call
                              when a block was added to the ledger

    ***************************************************************************/

    public this (immutable(ConsensusParams) params,
        UTXOSet utxo_set, IBlockStorage storage,
        EnrollmentManager enroll_man, TransactionPool pool,
        DataPayloadChecker payload_checker,
        void delegate (const ref Block, bool) @safe onAcceptedBlock = null)
    {
        this.params = params;
        this.utxo_set = utxo_set;
        this.storage = storage;
        this.enroll_man = enroll_man;
        this.slash_man = new SlashPolicy(this.enroll_man, params);
        this.pool = pool;
        this.onAcceptedBlock = onAcceptedBlock;
        this.payload_checker = payload_checker;
        if (!this.storage.load(params.Genesis))
            assert(0);

        // ensure latest checksum can be read
        if (!this.storage.readLastBlock(this.last_block))
            assert(0);
        log.info("Last known block: #{} ({})", this.last_block.header.height,
                 this.last_block.header.hashFull());

        Block gen_block;
        this.storage.readBlock(gen_block, Height(0));
        if (gen_block != cast()params.Genesis)
            throw new Exception("Genesis block loaded from disk is " ~
                "different from the one in the config file");

        // need to rebuild the UTXO set and Validator set,
        // starting from the genesis block
        if (this.utxo_set.length == 0)
        {
            ManagedDatabase.beginBatch();
            scope (failure) ManagedDatabase.rollback();

            // clear validator set
            this.enroll_man.removeAllValidators();

            Block last_read_block = gen_block;
            foreach (height; 0 .. this.last_block.header.height + 1)
            {
                Block block;
                this.storage.readBlock(block, Height(height));
                if (height == 0)
                {
                    if (auto reason = block.isGenesisBlockInvalidReason())
                        throw new Exception(
                            "Genesis block loaded from disk is invalid: " ~
                            reason);
                }
                else
                {
                    const active_enrollments = enroll_man.getValidatorCount(
                        block.header.height);

                    if (auto fail_reason = block.isInvalidReason(
                        last_read_block.header.height,
                        last_read_block.header.hashFull,
                        this.utxo_set.getUTXOFinder(),
                        active_enrollments,
                        &this.payload_checker.check))
                        throw new Exception(
                            "A block loaded from disk is invalid: " ~
                            fail_reason);
                }
                this.updateUTXOSet(block);
                this.updateValidatorSet(block);
                last_read_block = block;
            }
            ManagedDatabase.commitBatch();
        }
        else if (this.enroll_man.validatorCount() == 0)
        {
            // +1 because the genesis block counts as one
            const ulong block_count = this.last_block.header.height + 1;

            // we are only interested in the last 1008 blocks,
            // because that is the maximum length of an enrollment.
            const Height min_height =
                block_count >= this.params.ValidatorCycle
                ? Height(block_count - this.params.ValidatorCycle) : Height(0);

            // restore validator set from the blockchain.
            // using block_count, as the range is inclusive
            foreach (block_idx; min_height .. block_count)
            {
                Block block;
                this.storage.readBlock(block, block_idx);
                this.updateValidatorSet(block);
            }
        }

        Utils.getCollectorRegistry().addCollector(&this.collectTxStats);
        Utils.getCollectorRegistry().addCollector(&this.collectBlockStats);
    }

    /***************************************************************************

        Called when a consensus data set is externalized.

        This will create a new block and add it to the ledger.

        Params:
            data = the consensus data which was externalized

        Returns:
            true if the consensus data was accepted

    ***************************************************************************/

    public bool onExternalized (ConsensusData data)
        @trusted
    {
        auto block = makeNewBlock(this.last_block, data.tx_set, data.enrolls);
        return this.acceptBlock(block);
    }

    /***************************************************************************

        Add a block to the ledger.

        If the block fails verification, it is not added to the ledger.

        Params:
            block = the block to add

        Returns:
            true if the block was accepted

    ***************************************************************************/

    public bool acceptBlock (const ref Block block) @safe
    {
        if (auto fail_reason = this.validateBlock(block))
        {
            log.trace("Rejected block: {}: {}", fail_reason, block.prettify());
            return false;
        }

        this.addValidatedBlock(block);
        this.block_stats.increaseMetricBy!"agora_block_txs_amount_total"(
            getUnspentAmount(block.txs));
        this.block_stats.increaseMetricBy!"agora_block_txs_total"(
            block.txs.length);
        this.block_stats.increaseMetricBy!"agora_block_externalized_total"(1);
        return true;
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
        this.tx_stats.increaseMetricBy!"agora_transactions_received_total"(1);
        const Height expected_height = Height(this.getBlockHeight() + 1);
        auto reason = tx.isInvalidReason(this.utxo_set.getUTXOFinder(),
            expected_height, &this.payload_checker.check);

        if (reason !is null || !this.pool.add(tx))
        {
            log.info("Rejected tx. Reason: {}. Tx: {}",
                reason !is null ? reason : "double-spend", tx);
            this.tx_stats.increaseMetricBy!"agora_transactions_rejected_total"(1);
            return false;
        }

        this.tx_stats.increaseMetricBy!"agora_transactions_accepted_total"(1);
        return true;
    }

    /***************************************************************************

        Add a validated block to the Ledger,
        and add all of its outputs to the UTXO set.
        If there are any enrollments in the block,
        add enrollments to the validator set.
        If not null call the `onAcceptedBlock` delegate.

        Params:
            block = the block to add

    ***************************************************************************/

    private void addValidatedBlock (const ref Block block) @safe
    {
        if (!this.storage.saveBlock(block))
            assert(0, format!"Failed to save block: %s"(prettify(block)));

        auto old_count = this.enroll_man.validatorCount();

        ManagedDatabase.beginBatch();
        {
            // rollback on failure within the scope of the db transactions
            scope (failure) ManagedDatabase.rollback();
            this.updateUTXOSet(block);
            this.updateValidatorSet(block);
            ManagedDatabase.commitBatch();
        }

        this.block_stats.setMetricTo!"agora_block_enrollments_gauge"(
            this.enroll_man.validatorCount());
        // there was a change in the active validator set
        bool validators_changed = block.header.enrollments.length > 0
            || this.enroll_man.validatorCount() != old_count;

        // read back and cache the last block
        if (!this.storage.readLastBlock(this.last_block))
            assert(0, format!"Failed to read last block: %s"(prettify(this.last_block)));

        if (this.onAcceptedBlock !is null)
            this.onAcceptedBlock(block, validators_changed);
    }

    mixin DefineCollectorForStats!("block_stats", "collectBlockStats");

    /***************************************************************************

        Collect all ledger & mempool stats into the collector

        Params:
            collector = the Collector to collect the stats into

    ***************************************************************************/

    private void collectTxStats (Collector collector)
    {
        this.tx_stats.setMetricTo!"agora_transactions_poolsize_gauge"(
            this.pool.length());
        this.tx_stats.setMetricTo!"agora_transactions_amount_gauge"(
            getUnspentAmount(this.pool));
        foreach (stat; this.tx_stats.getStats())
            collector.collect(stat.value);
    }

    /// Stats helper: return the total unspent amount
    private ulong getUnspentAmount (TxRange)(ref TxRange transactions)
    {
        Amount tx_amount;
        foreach (const ref Transaction tx; transactions)
            getSumOutput(tx, tx_amount);
        return to!ulong(tx_amount.toString());
    }

    /***************************************************************************

        Update the UTXO set based on the block's transactions

        Params:
            block = the block to update the UTXO set with

    ***************************************************************************/

    protected void updateUTXOSet (const ref Block block) @safe
    {
        const height = block.header.height;
        // add the new UTXOs
        block.txs.each!(tx => this.utxo_set.updateUTXOCache(tx, height));

        // remove the TXs from the Pool
        block.txs.each!(tx => this.pool.remove(tx));
    }

    /***************************************************************************

        Update the active validator set

        Params:
            block = the block to update the Validator set with

    ***************************************************************************/

    protected void updateValidatorSet (const ref Block block) @safe
    {
        this.enroll_man.clearExpiredValidators(block.header.height);
        PublicKey pubkey = this.enroll_man.getEnrollmentPublicKey();
        UTXO[Hash] utxos = this.utxo_set.getUTXOs(pubkey);
        foreach (idx, ref enrollment; block.header.enrollments)
        {
            UTXO utxo;
            if (!this.utxo_set.peekUTXO(enrollment.utxo_key, utxo))
                assert(0);

            this.enroll_man.removeEnrollment(enrollment.utxo_key);
            if (auto r = this.enroll_man.addValidator(enrollment, utxo.output.address,
                block.header.height, &this.utxo_set.peekUTXO, utxos))
            {
                log.fatal("Error while adding a new validator: {}", r);
                log.fatal("Enrollment #{}: {}", idx, enrollment);
                log.fatal("Validated block: {}", block);
                assert(0);
            }
        }
    }

    /***************************************************************************

        Collect up to a maximum number of transactions to nominate

        Params:
            txs = will contain the transaction set to nominate,
                  or empty if not enough txs were found
            max_txs = the maximum number of transactions to prepare.

    ***************************************************************************/

    public void prepareNominatingSet (ref ConsensusData data, ulong max_txs)
        @safe
    {
        data = ConsensusData.init;
        const next_height = Height(this.getBlockHeight() + 1);
        auto utxo_finder = this.utxo_set.getUTXOFinder();

        this.enroll_man.getEnrollments(data.enrolls,
            Height(this.getBlockHeight()));

        // get information about validators not revealing a preimage timely
        this.slash_man.getMissingValidators(data.missing_validators,
            this.getBlockHeight());

        foreach (ref Transaction tx; this.pool)
        {
            if (auto reason = tx.isInvalidReason(utxo_finder, next_height, &this.payload_checker.check))
                log.trace("Rejected invalid ('{}') tx: {}", reason, tx);
            else
                data.tx_set ~= tx;

            if (data.tx_set.length >= max_txs)
            {
                data.tx_set.sort();
                return;
            }
        }
    }

    /***************************************************************************

        Check whether the consensus data is valid.

        Params:
            data = consensus data

        Returns:
            the error message if validation failed, otherwise null

    ***************************************************************************/

    public string validateConsensusData (ConsensusData data) @trusted
    {
        const expect_height = Height(this.getBlockHeight() + 1);
        auto utxo_finder = this.utxo_set.getUTXOFinder();

        foreach (const ref tx; data.tx_set)
        {
            if (auto fail_reason = tx.isInvalidReason(utxo_finder, expect_height, &this.payload_checker.check))
                return fail_reason;
        }

        size_t active_enrollments = enroll_man.getValidatorCount(expect_height);

        if (data.enrolls.length + active_enrollments < Enrollment.MinValidatorCount)
            return "Enrollment: Insufficient number of active validators";

        foreach (const ref enroll; data.enrolls)
        {
            UTXO utxo_value;
            assert(this.utxo_set.peekUTXO(enroll.utxo_key, utxo_value));
            if (auto fail_reason = this.enroll_man.isInvalidCandidateReason(
                enroll, utxo_value.output.address, expect_height, utxo_finder))
                return fail_reason;
        }

        return null;
    }

    /***************************************************************************

        Check whether the slashing data is valid.

        Params:
            data = consensus data

        Returns:
            the error message if validation failed, otherwise null

    ***************************************************************************/

    public string validateSlashingData (in ConsensusData data) @safe
    {
        return this.slash_man.isInvalidPreimageRootReason(this.getBlockHeight(),
                data.missing_validators);
    }

    /***************************************************************************

        Check whether the block is valid.

        Params:
            block = the block to check

        Returns:
            the error message if block validation failed, otherwise null

    ***************************************************************************/

    public string validateBlock (const ref Block block) nothrow @safe
    {
        size_t active_enrollments = enroll_man.getValidatorCount(
                block.header.height);

        return block.isInvalidReason(this.last_block.header.height,
            this.last_block.header.hashFull,
            this.utxo_set.getUTXOFinder(),
            active_enrollments,
            &this.payload_checker.check);
    }

    /***************************************************************************

        Returns:
            latest block height

    ***************************************************************************/

    public Height getBlockHeight () @safe nothrow
    {
        return this.last_block.header.height;
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

        const(Block) readBlock (Height height)
        {
            Block block;
            if (!this.storage.tryReadBlock(block, height))
                assert(0);
            return block;
        }

        return iota(start_height, this.getBlockHeight() + 1)
            .map!(idx => readBlock(Height(idx)));
    }

    /***************************************************************************

        Get the array of hashs the merkle path.

        Params:
            block_height = block height with transaction hash
            hash         = transaction hash

        Returns:
            the array of hashs the merkle path

    ***************************************************************************/

    public Hash[] getMerklePath (Height block_height, in Hash hash) @safe nothrow
    {
        if (this.getBlockHeight() < block_height)
            return null;

        Block block;
        if (!this.storage.tryReadBlock(block, block_height))
            return null;

        size_t index = block.findHashIndex(hash);
        if (index >= block.txs.length)
            return null;
        return block.getMerklePath(index);
    }

    /***************************************************************************

        Generate the random seed reduced from the preimages for the provided
        block height.

        Params:
            height = the desired block height to look up the images for

        Returns:
            the random seed

    ***************************************************************************/

    public Hash getValidatorRandomSeed (Height height) nothrow
    {
        Hash[] keys;
        if (!this.enroll_man.getEnrolledUTXOs(keys) || keys.length == 0)
        {
            log.fatal("Could not retrieve enrollments / no enrollments found");
            assert(0);
        }

        return this.enroll_man.getRandomSeed(keys, height);
    }
}

/// Note: these unittests historically assume a block always contains
/// 8 transactions - hence the use of `TxsInTestBlock` appearing everywhere.
version (unittest)
{
    /// simulate block creation as if a nomination and externalize round completed
    private void forceCreateBlock (Ledger ledger)
    {
        ConsensusData data;
        ledger.prepareNominatingSet(data, Block.TxsInTestBlock);
        assert(data.tx_set.length == Block.TxsInTestBlock);
        assert(ledger.onExternalized(data));
    }

    /// A `Ledger` with sensible defaults for `unittest` blocks
    private final class TestLedger : Ledger
    {
        public this (KeyPair key_pair,
            const(Block)[] blocks = null,
            immutable(ConsensusParams) params_ = null)
        {
            const params = (params_ !is null)
                ? params_
                : (blocks.length > 0
                   // Use the provided Genesis block
                   ? new immutable(ConsensusParams)(cast(immutable)blocks[0], WK.Keys.CommonsBudget.address)
                   // Use the unittest genesis block
                   : new immutable(ConsensusParams)());

            super(params, new UTXOSet(":memory:"),
                new MemBlockStorage(blocks),
                new EnrollmentManager(":memory:", key_pair, params),
                new TransactionPool(":memory:"),
                new DataPayloadChecker());
        }
    }
}

///
unittest
{
    scope ledger = new TestLedger(WK.Keys.NODE2);
    assert(ledger.getBlockHeight() == 0);

    auto blocks = ledger.getBlocksFrom(Height(0)).take(10);
    assert(blocks[$ - 1] == ledger.params.Genesis);

    // generate enough transactions to form a block
    Transaction[] last_txs;
    void genBlockTransactions (size_t count)
    {
        assert(count > 0);

        // Special case for genesis
        if (!last_txs.length)
        {
            last_txs = genesisSpendable().take(Block.TxsInTestBlock).enumerate()
                .map!(en => en.value.refund(WK.Keys.A.address).sign())
                .array();
            last_txs.each!(tx => ledger.acceptTransaction(tx));
            ledger.forceCreateBlock();
            count--;
        }

        foreach (_; 0 .. count)
        {
            last_txs = last_txs.map!(tx => TxBuilder(tx).sign()).array();
            last_txs.each!(tx => assert(ledger.acceptTransaction(tx)));
            ledger.forceCreateBlock();
        }
    }

    genBlockTransactions(2);
    blocks = ledger.getBlocksFrom(Height(0)).take(10);
    assert(blocks[0] == ledger.params.Genesis);
    assert(blocks.length == 3);  // two blocks + genesis block

    /// now generate 98 more blocks to make it 100 + genesis block (101 total)
    genBlockTransactions(17);
    assert(ledger.getBlockHeight() == 19);

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

    blocks = ledger.getBlocksFrom(Height(5)).takeExactly(10);
    assert(blocks[0].header.height == 5);
    assert(blocks.length == 10);

    blocks = ledger.getBlocksFrom(Height(15)).take(10);  // only 6 left from here (block 100 included)
    assert(blocks.front.header.height == 15);
    assert(blocks.walkLength() == 5);

    blocks = ledger.getBlocksFrom(Height(18)).take(10);  // only 2 left from here (ditto)
    assert(blocks.front.header.height == 18);
    assert(blocks.walkLength() == 2);

    blocks = ledger.getBlocksFrom(Height(19)).take(10);  // only 1 block available
    assert(blocks.front.header.height == 19);
    assert(blocks.walkLength() == 1);

    // over the limit => return up to the highest block
    assert(ledger.getBlocksFrom(Height(0)).take(1000).walkLength() == 20);

    // higher index than available => return nothing
    assert(ledger.getBlocksFrom(Height(1000)).take(10).walkLength() == 0);
}

// Reject a transaction whose output value is 0
unittest
{
    scope ledger = new TestLedger(WK.Keys.Genesis);

    // Valid case
    auto txs = genesisSpendable().map!(txb => txb.sign()).array();
    txs.each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();
    auto blocks = ledger.getBlocksFrom(Height(0)).take(10);
    assert(blocks.length == 2);

    // Invalid case
    txs = txs.map!(tx => TxBuilder(tx).sign()).array();
    foreach (ref tx; txs)
    {
        foreach (ref output; tx.outputs)
            output.value = Amount(0);
        foreach (ref input; tx.inputs)
            input.signature = WK.Keys.Genesis.secret.sign(hashFull(tx)[]);
    }

    txs.each!(tx => assert(!ledger.acceptTransaction(tx)));
    blocks = ledger.getBlocksFrom(Height(0)).take(10);
    assert(blocks.length == 2);
}

/// basic block verification
unittest
{
    scope ledger = new TestLedger(WK.Keys.NODE2);

    Block invalid_block;  // default-initialized should be invalid
    assert(!ledger.acceptBlock(invalid_block));

    auto txs = genesisSpendable().map!(txb => txb.sign()).array();
    auto valid_block = makeNewBlock(ledger.params.Genesis, txs);
    assert(ledger.acceptBlock(valid_block));
}

/// Merkle Proof
unittest
{
    scope ledger = new TestLedger(WK.Keys.NODE2);

    auto txs = genesisSpendable().map!(txb => txb.sign()).array();
    txs.each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();

    Hash[] hashes;
    hashes.reserve(txs.length);
    foreach (ref e; txs)
        hashes ~= hashFull(e);

    // transactions are ordered lexicographically by hash in the Merkle tree
    hashes.sort!("a < b");

    const Hash ha = hashes[0];
    const Hash hb = hashes[1];
    const Hash hc = hashes[2];
    const Hash hd = hashes[3];
    const Hash he = hashes[4];
    const Hash hf = hashes[5];
    const Hash hg = hashes[6];
    const Hash hh = hashes[7];

    const Hash hab = hashMulti(ha, hb);
    const Hash hcd = hashMulti(hc, hd);
    const Hash hef = hashMulti(he, hf);
    const Hash hgh = hashMulti(hg, hh);

    const Hash habcd = hashMulti(hab, hcd);
    const Hash hefgh = hashMulti(hef, hgh);

    const Hash habcdefgh = hashMulti(habcd, hefgh);

    Hash[] merkle_path;
    merkle_path = ledger.getMerklePath(Height(1), hc);
    assert(merkle_path.length == 3);
    assert(merkle_path[0] == hd);
    assert(merkle_path[1] == hab);
    assert(merkle_path[2] == hefgh);
    assert(habcdefgh == Block.checkMerklePath(hc, merkle_path, 2));
    assert(habcdefgh != Block.checkMerklePath(hd, merkle_path, 2));

    merkle_path = ledger.getMerklePath(Height(1), he);
    assert(merkle_path.length == 3);
    assert(merkle_path[0] == hf);
    assert(merkle_path[1] == hgh);
    assert(merkle_path[2] == habcd);
    assert(habcdefgh == Block.checkMerklePath(he, merkle_path, 4));
    assert(habcdefgh != Block.checkMerklePath(hf, merkle_path, 4));

    merkle_path = ledger.getMerklePath(Height(1), Hash.init);
    assert(merkle_path.length == 0);
}

/// Situation: Ledger is constructed with blocks present in storage
/// Expectation: The UTXOSet is populated with all up-to-date UTXOs
unittest
{
    import agora.consensus.data.genesis.Test;

    // Cannot use literals: https://issues.dlang.org/show_bug.cgi?id=20938
    const(Block)[] blocks = [ GenesisBlock ];
    auto txs = GenesisBlock.spendable().map!(txb => txb.sign()).array();
    blocks ~= makeNewBlock(blocks[$ - 1], txs);
    // Make 3 more blocks to put in storage
    foreach (idx; 2 .. 5)
    {
        txs = blocks[$ - 1].spendable().map!(txb => txb.sign()).array();
        blocks ~= makeNewBlock(blocks[$ - 1], txs);
    }

    // And provide it to the ledger
    scope ledger = new TestLedger(WK.Keys.NODE2, blocks);

    assert(ledger.utxo_set.length
           == /* Genesis, Frozen */ 6 + 8 /* Block #1 Payments*/);

    // Ensure that all previously-generated outputs are in the UTXO set
    {
        auto findUTXO = ledger.utxo_set.getUTXOFinder();
        UTXO utxo;
        assert(
            txs.all!(
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

version (unittest)
private Transaction[] makeTransactionForFreezing (
    const(KeyPair)[] in_key_pair,
    KeyPair[] out_key_pair,
    TxType tx_type,
    Transaction[] prev_txs,
    const Transaction default_tx)
{
    import std.conv;

    assert(in_key_pair.length == Block.TxsInTestBlock);
    assert(out_key_pair.length == Block.TxsInTestBlock);

    assert(prev_txs.length == 0 || prev_txs.length == Block.TxsInTestBlock);
    const TxCount = Block.TxsInTestBlock;

    Transaction[] transactions;

    // always use the same amount, for simplicity
    const Amount AmountPerTx = Amount.MinFreezeAmount;

    foreach (idx; 0 .. TxCount)
    {
        Input input;
        if (prev_txs.length == 0)  // refering to genesis tx's outputs
            input = Input(hashFull(default_tx), idx.to!uint);
        else  // refering to tx's in the previous block
            input = Input(hashFull(prev_txs[idx % Block.TxsInTestBlock]), 0);

        Transaction tx =
        {
            tx_type,
            [input],
            [Output(AmountPerTx, out_key_pair[idx % Block.TxsInTestBlock].address)]  // send to the same address
        };

        auto signature = in_key_pair[idx % Block.TxsInTestBlock].secret.sign(hashFull(tx)[]);
        tx.inputs[0].signature = signature;
        transactions ~= tx;

        // new transactions will refer to the just created transactions
        // which will be part of the previous block after the block is created
        if (Block.TxsInTestBlock == 1 ||  // special case
            (idx > 0 && ((idx + 1) % Block.TxsInTestBlock == 0)))
        {
            // refer to tx'es which will be in the previous block
            prev_txs = transactions[$ - Block.TxsInTestBlock .. $];
        }
    }
    return transactions;
}

version (unittest)
private KeyPair[] getRandomKeyPairs ()
{
    return WK.Keys.byRange().take(8).array();
}

/// Situation : Create two blocks, one containing only `Payment` transactions,
///             the other containing only `Freeze` ones
/// Expectation: Block creation succeeds
unittest
{
    scope ledger = new TestLedger(WK.Keys.NODE2);

    // Generate payment transactions to the first 8 well-known keypairs
    auto txs = genesisSpendable().enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();
    txs.each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();
    assert(ledger.getBlockHeight() == 1);
    auto blocks = ledger.getBlocksFrom(Height(0)).take(10).array;
    assert(blocks.length == 2);
    assert(blocks[1].header.height == 1);

    // Now generate a block with only freezing transactions
    txs.enumerate()
        .map!(en => TxBuilder(en.value)
              .refund(WK.Keys[Block.TxsInTestBlock + en.index].address)
              .sign(TxType.Freeze))
        .each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();
    assert(ledger.getBlockHeight() == 2);
    blocks = ledger.getBlocksFrom(Height(0)).take(10).array;
    assert(blocks.length == 3);
    assert(blocks[2].header.height == 2);
}

// Create freeze transactions and create enrollments to
// test if it is stored in a block.
unittest
{
    import agora.common.crypto.ECC;
    import agora.common.crypto.Schnorr;

    auto validator_cycle = 10;
    auto params = new immutable(ConsensusParams)(validator_cycle);
    scope ledger = new TestLedger(WK.Keys.NODE2);

    KeyPair[] splited_keys = getRandomKeyPairs();
    KeyPair[] in_key_pairs_normal;
    KeyPair[] out_key_pairs_normal;
    Transaction[] last_txs_normal;
    KeyPair[] in_key_pairs_freeze;
    KeyPair[] out_key_pairs_freeze;
    Transaction[] last_txs_freeze;

    Transaction[] splited_txex;

    in_key_pairs_normal.length = 0;
    foreach (idx; 0 .. Block.TxsInTestBlock)
        in_key_pairs_normal ~= splited_keys[0];

    out_key_pairs_normal = getRandomKeyPairs();

    // generate normal transactions to form a block
    void genNormalBlockTransactions (size_t count)
    {
        foreach (idx; 0 .. count)
        {
            auto txes = makeTransactionForFreezing (
                in_key_pairs_normal,
                out_key_pairs_normal,
                TxType.Payment,
                last_txs_normal,
                splited_txex[0]);

            txes.each!((tx)
                {
                    assert(ledger.acceptTransaction(tx));
                });
            ledger.forceCreateBlock();

            // keep track of last tx's to chain them to
            last_txs_normal = txes[$ - Block.TxsInTestBlock .. $];

            in_key_pairs_normal = out_key_pairs_normal;
            out_key_pairs_normal = getRandomKeyPairs();
        }
    }

    in_key_pairs_freeze.length = 0;
    foreach (idx; 0 .. Block.TxsInTestBlock)
        in_key_pairs_freeze ~= splited_keys[1];

    out_key_pairs_freeze = getRandomKeyPairs();

    // generate freezing transactions to form a block
    void genBlockTransactionsFreeze (size_t count, TxType tx_type)
    {
        foreach (idx; 0 .. count)
        {
            auto txes = makeTransactionForFreezing (
                in_key_pairs_freeze,
                out_key_pairs_freeze,
                tx_type,
                last_txs_freeze,
                splited_txex[1]);

            txes.each!((tx)
                {
                    assert(ledger.acceptTransaction(tx));
                });
            ledger.forceCreateBlock();

            // keep track of last tx's to chain them to
            last_txs_freeze = txes[$ - Block.TxsInTestBlock .. $];

            in_key_pairs_freeze = out_key_pairs_freeze;
            out_key_pairs_freeze = getRandomKeyPairs();
        }
    }

    // Divide 8 'Outputs' that are included in Genesis Block by 40,000
    // It generates eight addresses and eight transactions,
    // and one transaction has eight Outputs with a value of 40,000 values.
    splited_txex = () {
        Transaction[] txs;
        foreach (idx; 0 .. Block.TxsInTestBlock)
        {
            txs ~= TxBuilder(params.Genesis.txs[1], idx)
                .split(splited_keys[idx].address.repeat(Block.TxsInTestBlock))
                .sign();
        }
        return txs;
    }();
    splited_txex.each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();
    assert(ledger.getBlockHeight() == 1);

    genNormalBlockTransactions(1);
    assert(ledger.getBlockHeight() == 2);

    genBlockTransactionsFreeze(1, TxType.Freeze);
    assert(ledger.getBlockHeight() == 3);

    auto blocks = ledger.getBlocksFrom(Height(0)).take(10);

    // make enrollments
    KeyPair[] enroll_key_pair;
    foreach (txid, tx; blocks[3].txs)
        foreach (key_pair; in_key_pairs_freeze)
            if (tx.outputs[0].address == key_pair.address)
                enroll_key_pair ~= key_pair;

    const utxo_hashes = [
        UTXO.getHash(hashFull(blocks[3].txs[0]), 0),
        UTXO.getHash(hashFull(blocks[3].txs[1]), 0),
        UTXO.getHash(hashFull(blocks[3].txs[2]), 0),
    ];

    Enrollment[] enrollments ;
    foreach (index; 0 .. 3)
        enrollments ~= EnrollmentManager.makeEnrollment(
            enroll_key_pair[index], utxo_hashes[index], params.ValidatorCycle);

    auto findUTXO = ledger.utxo_set.getUTXOFinder();
    foreach (index, const ref e; enrollments)
        assert(ledger.enroll_man.addEnrollment(e, enroll_key_pair[index].address,
                Height(3), findUTXO));

    Enrollment stored_enroll;
    foreach (idx, hash; utxo_hashes)
    {
        stored_enroll = ledger.enroll_man.getEnrollment(hash);
        assert(stored_enroll == enrollments[idx]);
    }

    genNormalBlockTransactions(1);
    assert(ledger.getBlockHeight() == 4);

    // Check if there are any unregistered enrollments
    Enrollment[] unreg_enrollments;
    assert(ledger.enroll_man.getEnrollments(unreg_enrollments,
        ledger.getBlockHeight()) is null);
    auto block_4 = ledger.getBlocksFrom(Height(4));
    enrollments.sort!("a.utxo_key < b.utxo_key");
    assert(block_4[0].header.enrollments == enrollments);

    genNormalBlockTransactions(validator_cycle - 1);
    Hash[] keys;
    assert(ledger.enroll_man.getEnrolledUTXOs(keys));
    assert(keys.length == /* Genesis */ 6 + 3 /* New ones */);
    assert(ledger.getBlockHeight() == validator_cycle + 4 - 1);
}

// Return Genesis block plus 'count' number of blocks
version (unittest)
private immutable(Block)[] genBlocksToIndex (
    KeyPair key_pair, size_t count, scope immutable(ConsensusParams) params)
{
    const(Block)[] blocks = [ params.Genesis ];

    foreach (_; 0 .. count)
    {
        auto txs = blocks[$ - 1].spendable().map!(txb => txb.sign());

        const NoEnrollments = null;
        blocks ~= makeNewBlock(blocks[$ - 1], txs, NoEnrollments);
    }

    return blocks.assumeUnique;
}

/// test enrollments in the genesis block
unittest
{
    import agora.common.BitField;
    import agora.common.Serializer;
    import std.exception;

    // Default test genesis block has 6 validators
    {
        scope ledger = new TestLedger(WK.Keys.A);
        Hash[] keys;
        assert(ledger.enroll_man.getEnrolledUTXOs(keys));
        assert(keys.length == 6);
    }

    // One block before `ValidatorCycle`, validator is still active
    {
        const ValidatorCycle = 10;
        auto key_pair = KeyPair.random();
        auto params = new immutable(ConsensusParams)(ValidatorCycle);
        const blocks = genBlocksToIndex(key_pair, ValidatorCycle - 1, params);
        scope ledger = new TestLedger(WK.Keys.A, blocks, params);
        Hash[] keys;
        assert(ledger.enroll_man.getEnrolledUTXOs(keys));
        assert(keys.length == 6);
    }

    // Past `ValidatorCycle`, validator is inactive
    {
        const ValidatorCycle = 20;
        auto key_pair = KeyPair.random();
        auto params = new immutable(ConsensusParams)(ValidatorCycle);
        const blocks = genBlocksToIndex(key_pair, ValidatorCycle, params);
        // Enrollment: Insufficient number of active validators
        assertThrown!Exception(new TestLedger(WK.Keys.A, blocks, params));
    }
}

/// test atomicity of adding blocks and rolling back
unittest
{
    import agora.common.crypto.Key;
    import agora.common.Types;
    import agora.common.Hash;
    import std.conv;
    import std.exception;
    import std.range;

    static class ThrowingLedger : Ledger
    {
        bool throw_in_update_utxo;
        bool throw_in_update_validators;

        public this (KeyPair kp, const(Block)[] blocks, immutable(ConsensusParams) params)
        {
            super(params, new UTXOSet(":memory:"),
                new MemBlockStorage(blocks),
                new EnrollmentManager(":memory:", kp, params),
                new TransactionPool(":memory:"),
                new DataPayloadChecker());
        }

        override void updateUTXOSet (const ref Block block) @safe
        {
            super.updateUTXOSet(block);
            if (this.throw_in_update_utxo)
                throw new Exception("");
        }

        override void updateValidatorSet (const ref Block block) @safe
        {
            super.updateValidatorSet(block);
            if (this.throw_in_update_validators)
                throw new Exception("");
        }
    }

    const params = new immutable(ConsensusParams)();

    // normal test: UTXO set and Validator set updated
    {
        auto key_pair = KeyPair.random();
        const blocks = genBlocksToIndex(key_pair, params.ValidatorCycle, params);
        assert(blocks.length == params.ValidatorCycle + 1);  // +1 for genesis

        scope ledger = new ThrowingLedger(
            key_pair, blocks.takeExactly(params.ValidatorCycle), params);
        Hash[] keys;
        assert(ledger.enroll_man.getEnrolledUTXOs(keys));
        assert(keys.length == 6);
        auto utxos = ledger.utxo_set.getUTXOs(WK.Keys.Genesis.address);
        assert(utxos.length == 8);
        utxos.each!(utxo => assert(utxo.unlock_height == params.ValidatorCycle));

        auto next_block = blocks[$ - 1];
        ledger.addValidatedBlock(next_block);
        assert(ledger.last_block == cast()next_block);
        utxos = ledger.utxo_set.getUTXOs(WK.Keys.Genesis.address);
        assert(utxos.length == 8);
        utxos.each!(utxo => assert(utxo.unlock_height == params.ValidatorCycle + 1));
        assert(ledger.enroll_man.getEnrolledUTXOs(keys));
        assert(keys.length == 0);
    }

    // throws in updateUTXOSet() => rollback() called, UTXO set reverted,
    // Validator set was not modified
    {
        auto key_pair = KeyPair.random();
        const blocks = genBlocksToIndex(key_pair, params.ValidatorCycle, params);
        assert(blocks.length == params.ValidatorCycle + 1);  // +1 for genesis

        scope ledger = new ThrowingLedger(
            key_pair, blocks.takeExactly(params.ValidatorCycle), params);
        Hash[] keys;
        assert(ledger.enroll_man.getEnrolledUTXOs(keys));
        assert(keys.length == 6);
        auto utxos = ledger.utxo_set.getUTXOs(WK.Keys.Genesis.address);
        assert(utxos.length == 8);
        utxos.each!(utxo => assert(utxo.unlock_height == params.ValidatorCycle));

        ledger.throw_in_update_utxo = true;
        auto next_block = blocks[$ - 1];
        assertThrown!Exception(ledger.addValidatedBlock(next_block));
        assert(ledger.last_block == cast()blocks[$ - 2]);  // not updated
        utxos = ledger.utxo_set.getUTXOs(WK.Keys.Genesis.address);
        assert(utxos.length == 8);
        utxos.each!(utxo => assert(utxo.unlock_height == params.ValidatorCycle));  // reverted
        assert(ledger.enroll_man.getEnrolledUTXOs(keys));
        assert(keys.length == 6);  // not updated
    }

    // throws in updateValidatorSet() => rollback() called, UTXO set and
    // Validator set reverted
    {
        auto key_pair = KeyPair.random();
        const blocks = genBlocksToIndex(key_pair, params.ValidatorCycle, params);
        assert(blocks.length == params.ValidatorCycle + 1);  // +1 for genesis

        scope ledger = new ThrowingLedger(
            key_pair, blocks.takeExactly(params.ValidatorCycle), params);
        Hash[] keys;
        assert(ledger.enroll_man.getEnrolledUTXOs(keys));
        assert(keys.length == 6);
        auto utxos = ledger.utxo_set.getUTXOs(WK.Keys.Genesis.address);
        assert(utxos.length == 8);
        utxos.each!(utxo => assert(utxo.unlock_height == params.ValidatorCycle));

        ledger.throw_in_update_validators = true;
        auto next_block = blocks[$ - 1];
        assertThrown!Exception(ledger.addValidatedBlock(next_block));
        assert(ledger.last_block == cast()blocks[$ - 2]);  // not updated
        utxos = ledger.utxo_set.getUTXOs(WK.Keys.Genesis.address);
        assert(utxos.length == 8);
        utxos.each!(utxo => assert(utxo.unlock_height == params.ValidatorCycle));  // reverted
        assert(ledger.enroll_man.getEnrolledUTXOs(keys));
        assert(keys.length == 6);  // reverted
    }
}

/// throw if the gen block in block storage is different to the configured one
unittest
{
    import agora.consensus.data.genesis.Test;
    import std.conv;
    import agora.consensus.data.genesis.Coinnet : CoinGenesis = GenesisBlock;

    // ConsensusParams is instantiated by default with the test genesis block
    immutable params = new immutable(ConsensusParams)();
    assert(CoinGenesis != params.Genesis);

    try
    {
        scope ledger = new TestLedger(WK.Keys.A, [CoinGenesis], params);
        assert(0);
    }
    catch (Exception ex)
    {
        assert(ex.msg == "Genesis block loaded from disk is different from the one in the config file");
    }

    immutable good_params = new immutable(ConsensusParams)(CoinGenesis, WK.Keys.CommonsBudget.address);
    // will not fail
    scope ledger = new TestLedger(WK.Keys.A, [CoinGenesis], good_params);
    // Neither will the default
    scope other_ledger = new TestLedger(WK.Keys.A, [CoinGenesis]);
}

unittest
{
    scope ledger = new TestLedger(WK.Keys.NODE2);
    scope payload_checker = new DataPayloadChecker();

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
    Amount data_fee = payload_checker.getFee(data.length);

    // Generate a block with data stored transactions
    txs = txs.enumerate()
        .map!(en => TxBuilder(en.value)
              .draw(data_fee, [ledger.params.CommonsBudgetAddress])
              .sign(TxType.Payment, data))
              .array;
    txs.each!(tx => assert(ledger.acceptTransaction(tx)));
    ledger.forceCreateBlock();
    assert(ledger.getBlockHeight() == 2);
    auto blocks = ledger.getBlocksFrom(Height(0)).take(10).array;
    assert(blocks.length == 3);
    assert(blocks[2].header.height == 2);

    foreach (ref tx; blocks[2].txs)
    {
        assert(tx.type == TxType.Payment);
        assert(tx.outputs.length > 0);
        assert(tx.outputs[0].value == data_fee);
        assert(tx.outputs[0].address == ledger.params.CommonsBudgetAddress);
        assert(tx.payload.data == data);
    }

    // Generate a block to reuse transactions used for data storage
    txs = txs.enumerate()
        .map!(en => TxBuilder(en.value, 1)
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
    import agora.common.crypto.Schnorr;
    import agora.consensus.data.genesis.Test;
    import agora.consensus.data.PreImageInfo;
    import agora.consensus.PreImage;

    auto params = new immutable(ConsensusParams)();
    const(Block)[] blocks = [ GenesisBlock ];
    scope ledger = new TestLedger(WK.Keys.NODE2, blocks, params);

    Transaction[] genTransactions (Transaction[] txs)
    {
        return txs.enumerate()
            .map!(en => TxBuilder(en.value).refund(WK.Keys[en.index].address)
                .sign())
            .array;
    }

    Transaction[] genGeneralBlock (Transaction[] txs)
    {
        auto new_txs = genTransactions(txs);
        new_txs.each!(tx => assert(ledger.acceptTransaction(tx)));
        ledger.forceCreateBlock();
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
            .sign(TxType.Freeze)).array;
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

    foreach (height; 4 .. 20)
    {
        new_txs = genGeneralBlock(new_txs);
        assert(ledger.getBlockHeight() == Height(height));
    }

    // add four new enrollments
    Enrollment[] enrollments;
    PreImageCache[] caches;
    auto pairs = iota(4).map!(idx => WK.Keys[idx]).array;
    foreach (idx, kp; pairs)
    {
        auto pair = Pair.fromScalar(secretKeyToCurveScalar(kp.secret));
        auto cycle = PreImageCycle(
                0, 0,
                PreImageCache(PreImageCycle.NumberOfCycles, params.ValidatorCycle),
                PreImageCache(params.ValidatorCycle, 1));
        const seed = cycle.populate(pair.v, true);
        caches ~= cycle.preimages;
        auto enroll = EnrollmentManager.makeEnrollment(
            pair, utxos[idx], params.ValidatorCycle,
            seed, idx);
        assert(ledger.enroll_man.addEnrollment(enroll, kp.address, Height(1),
                &ledger.utxo_set.peekUTXO));
        enrollments ~= enroll;
    }

    foreach (idx, hash; utxos)
    {
        Enrollment stored_enroll = ledger.enroll_man.getEnrollment(hash);
        assert(stored_enroll == enrollments[idx]);
    }

    // create the 20th block to make the `Enrollment`s enrolled
    new_txs = genGeneralBlock(new_txs);
    assert(ledger.getBlockHeight() == Height(20));
    ledger.enroll_man.clearExpiredValidators(Height(20));
    auto b20 = ledger.getBlocksFrom(Height(20))[0];
    assert(b20.header.enrollments.length == 4);

    // block 21
    new_txs = genGeneralBlock(new_txs);
    assert(ledger.getBlockHeight() == Height(21));

    // check missing validators not revealing pre-images.
    // there are three missing validators at the height of 21.
    auto temp_txs = genTransactions(new_txs);
    temp_txs.each!(tx => assert(ledger.acceptTransaction(tx)));

    auto preimage = PreImageInfo(
        enrollments[0].utxo_key,
        caches[0][$ - 2],
        1);
    ledger.enroll_man.addPreimage(preimage);
    auto gotten_image =
        ledger.enroll_man.getValidatorPreimage(enrollments[0].utxo_key);
    assert(gotten_image == preimage);

    ConsensusData data;
    ledger.prepareNominatingSet(data, Block.TxsInTestBlock);
    assert(data.missing_validators.length == 3);
    assert(data.missing_validators == [0, 1, 2]);

    // check validity of slashing information
    assert(ledger.validateSlashingData(data) == null);
    ConsensusData forged_data = data;
    forged_data.missing_validators = [1, 2, 3];
    assert(ledger.validateSlashingData(forged_data) != null);

    // reveal preimages of all the validators
    foreach (idx, cache; caches[1 .. $])
    {
        preimage = PreImageInfo(
            enrollments[idx + 1].utxo_key,
            cache[$ - 2],
            1);
        ledger.enroll_man.addPreimage(preimage);
        gotten_image =
            ledger.enroll_man.getValidatorPreimage(enrollments[idx + 1].utxo_key);
        assert(gotten_image == preimage);
    }

    // there's no missing validator at the height of 11
    // after revealing preimages
    temp_txs.each!(tx => ledger.pool.remove(tx));
    temp_txs = genTransactions(new_txs);
    temp_txs.each!(tx => assert(ledger.acceptTransaction(tx)));

    ledger.prepareNominatingSet(data, Block.TxsInTestBlock);
    assert(data.missing_validators.length == 0);
}
