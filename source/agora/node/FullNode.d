/*******************************************************************************

    Implementation of the full node's API.

    See `agora.api.Validator` for a full description of the differences between
    a full node and a validator.

    Dependency_injection:
      To make the code testable, this classes exposes a few functions which are
      used to perform dependency injection. Those functions all follow the same
      pattern: they are `protected`, and called `makeXXX`.
      They can rely on both `this.config` and `this.params` fields being set.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.node.FullNode;

import agora.api.FullNode;
import agora.api.Handlers;
import agora.consensus.data.Block;
import agora.common.Amount;
import agora.common.BanManager;
import agora.common.Config;
import agora.common.ManagedDatabase;
import agora.common.Metadata;
import agora.common.Set;
import agora.common.VibeTask;
import agora.common.Types;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Params;
import agora.consensus.data.PreImageInfo;
import agora.consensus.data.Transaction;
import agora.consensus.Fee;
import agora.consensus.state.UTXOSet;
import agora.consensus.EnrollmentManager;
import agora.consensus.Fee;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.network.Client;
import agora.network.Clock;
import agora.network.Manager;
import agora.node.BlockStorage;
import agora.node.Ledger;
import agora.node.TransactionPool;
import agora.node.TransactionRelayer;
import agora.script.Engine;
import agora.serialization.Serializer;
import agora.stats.App;
import agora.stats.Block;
import agora.stats.EndpointReq;
import agora.stats.Server;
import agora.stats.Tx;
import agora.stats.Utils;
import agora.stats.Validator;
import agora.utils.Log;
import agora.utils.PrettyPrinter;
import agora.utils.Utility;

import scpd.types.Utils;

import vibe.data.json;
import vibe.web.rest;
import vibe.http.common;

import std.algorithm;
import std.conv : to, text;
import std.exception;
import std.file;
import std.format;
import std.path : buildPath;
import std.range;

import core.time;

/// Maximum number of blocks that will be sent in a call to getBlocksFrom()
private enum uint MaxBatchBlocksSent = 20;

/// Maximum number of transactions that will be sent in a call to
/// getTransactionByHash
private enum uint MaxBatchTranscationsSent = 100;

/*******************************************************************************

    Implementation of the FullNode API

    This class implements the business code of the FullNode.
    Communication with the other nodes is handled by the `Network` class.

*******************************************************************************/

public class FullNode : API
{
    /// Logger instance
    protected Logger log;

    /// Config instance
    protected Config config;

    /// Parameters for consensus-critical constants
    protected immutable(ConsensusParams) params;

    /// Task manager
    protected ITaskManager taskman;

    /// Timer this node has started
    protected ITimer[] timers;

    /// Clock instance
    protected Clock clock;

    /// Network of connected nodes
    protected NetworkManager network;

    /// Metadata instance
    protected Metadata metadata;

    /// Transaction pool
    protected TransactionPool pool;

    /// The Ledger is the main class driving consensus
    protected Ledger ledger;

    /// Enrollment manager
    protected EnrollmentManager enroll_man;

    /// The checker of transaction data payload
    protected FeeManager fee_man;

    /// Set of unspent transaction outputs
    protected UTXOSet utxo_set;

    /// Script execution engine
    protected Engine engine;

    /// Transaction relayer
    protected TransactionRelayer transaction_relayer;

    /***************************************************************************

        Persistence-related fields

        The node implement persistence through 3 databases.

        The blockchain data is binary serialized in a custom format to the disk
        to allow disk space usage to be reduced, as some data can be pruned in
        the long run, and there's almost no overhead in the binary serializer.
        Deleting the blockchain data invalidates both state and cache DB.

        State data, which is derived from the blockchain, such as UTXO set and
        validator set, are stored in the `"state DB". The state DB can be
        removed, either by user action or if found corrupted or inconsistent
        with the blockchain data. In such an event, the Ledger would rebuild
        it from scratch using the blockchain data, an operation which might
        take some time dependening on the number of blocks.

        Cache data is transient data that the node can reasonably loose without
        compromising its role. This includes the pools (enrollments and txs),
        as well as any additional metadata, for example peer list.

    ***************************************************************************/

    protected IBlockStorage storage;

    /// Ditto
    protected ManagedDatabase stateDB;

    /// Ditto
    protected ManagedDatabase cacheDB;

    /***************************************************************************

        Stats-related fields

        Those fields are used to expose internal statistics about the node on
        an HTTP interface that is ultimately queried by a Prometheus server.
        They may be unused if the stats interface is not enabled in the config.

    ***************************************************************************/

    protected StatsServer stats_server;

    /// Ditto
    protected ApplicationStats app_stats;

    /// Ditto
    protected EndpointRequestStats endpoint_request_stats;

    /// Ditto
    private TxStats tx_stats;

    /// Ditto
    private BlockStats block_stats;

    /// Ditto
    private ValidatorPreimagesStats validator_preimages_stats;

    /// Ditto
    private ValidatorCountStats validator_count_stats;


    /***************************************************************************

        List of handlers for specific actions

        Contains network client to servers that are interested in a specific
        event, such as block externalization.
        Those fields are populated based on the `event_handlers` configuration
        section, with one sub-section per event type.

        See_Also:
          https://github.com/bosagora/stoa

    ***************************************************************************/

    protected BlockExternalizedHandler[Address] block_handlers;

    /// Ditto
    protected BlockHeaderUpdatedHandler[Address] block_header_handlers;

    /// Ditto
    protected PreImageReceivedHandler[Address] preimage_handlers;

    /// Ditto
    protected TransactionReceivedHandler[Address] transaction_handlers;


    /***************************************************************************

        Constructor

        Params:
            config = Config instance

    ***************************************************************************/

    public this (Config config)
    {
        // Not at global scope because it would conflict with our `Clock` type
        import std.datetime.systime : SysTime, unixTimeToStdTime;
        import std.datetime.timezone: UTC;

        this.config = config;
        this.log = this.makeLogger();
        this.params = FullNode.makeConsensusParams(config);

        this.stateDB = this.makeStateDB();
        this.cacheDB = this.makeCacheDB();
        this.taskman = this.makeTaskManager();
        this.clock = this.makeClock(this.taskman);
        this.metadata = this.makeMetadata();
        this.network = this.makeNetworkManager(this.metadata, this.taskman, this.clock);
        this.storage = this.makeBlockStorage();
        this.fee_man = this.makeFeeManager();
        this.utxo_set = this.makeUTXOSet();
        this.pool = this.makeTransactionPool();
        this.enroll_man = this.makeEnrollmentManager();
        this.transaction_relayer = this.makeTransactionRelayer();
        const ulong StackMaxTotalSize = 16_384;
        const ulong StackMaxItemSize = 512;
        this.engine = new Engine(StackMaxTotalSize, StackMaxItemSize);
        if (!config.validator.enabled)
            this.ledger = new Ledger(params, this.engine, this.utxo_set,
                this.storage, this.enroll_man, this.pool, this.fee_man, this.clock,
                config.node.block_time_offset_tolerance, &this.onAcceptedBlock);

        // If we have handlers defined in the config
        if (config.event_handlers.length > 0)
        {
            // Make `BlockExternalizedHandler`s from config
            config.event_handlers.filter!(h => h.handler_type == HandlerType.block_externalized)
                .each!(handler => handler.handler_addresses
                    .each!((string address) =>
                        this.block_handlers[address] = this.network.getBlockExternalizedHandler(address)));

            // Make `BlockHeaderUpdatedHandler`s from config
            config.event_handlers.filter!(h => h.handler_type == HandlerType.block_header_updated)
                .each!(handler => handler.handler_addresses
                    .each!((string address) =>
                        this.block_header_handlers[address] = this.network.getBlockHeaderUpdatedHandler(address)));

            // Make `PreImageReceivedHandler`s from config
            config.event_handlers.filter!(h => h.handler_type == HandlerType.preimage_received)
                .each!(handler => handler.handler_addresses
                    .each!((string address) =>
                        this.preimage_handlers[address] = this.network.getPreImageReceivedHandler(address)));

            // Make `TransactionReceivedHandler`s from config
            config.event_handlers.filter!(h => h.handler_type == HandlerType.transaction_received)
                .each!(handler => handler.handler_addresses
                    .each!((string address) =>
                        this.transaction_handlers[address] = this.network.getTransactionReceivedHandler(address)));
        }

        Utils.getCollectorRegistry().addCollector(&this.collectAppStats);
        Utils.getCollectorRegistry().addCollector(&this.collectStats);
        Utils.getCollectorRegistry().addCollector(&this.collectTxStats);
        Utils.getCollectorRegistry().addCollector(&this.collectBlockStats);
        Utils.getCollectorRegistry().addCollector(&this.collectValidatorStats);

        enum build_version = import(VersionFileName);
        this.app_stats.setMetricTo!"agora_application_info"(
            1, // Unused, see article linked in the struct's documentationx
            build_version,
            __TIMESTAMP__, __VERSION__.to!string,
            config.validator.enabled
                ? config.validator.key_pair.address.toString() : null,
            SysTime(unixTimeToStdTime(this.params.GenesisTimestamp), UTC()).toISOString(),
        );
    }

    mixin DefineCollectorForStats!("app_stats", "collectAppStats");
    mixin DefineCollectorForStats!("endpoint_request_stats", "collectStats");
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
            this.getUnspentAmount(this.pool));
        foreach (stat; this.tx_stats.getStats())
            collector.collect(stat.value);
    }

    /// Stats helper: return the total unspent amount
    private ulong getUnspentAmount (TxRange) (ref TxRange transactions)
    {
        Amount tx_amount;
        foreach (const ref Transaction tx; transactions)
            getSumOutput(tx, tx_amount);
        return to!ulong(tx_amount.toString());
    }

    /***************************************************************************

        Collect all validator & preimage stats into the collector

        Params:
            collector = the Collector to collect the stats into

    ***************************************************************************/

    private void collectValidatorStats (Collector collector)
    {
        auto validators = this.ledger.getValidators(this.ledger.getBlockHeight() + 1);

        foreach (const ref val; validators)
            this.validator_preimages_stats.setMetricTo!"agora_preimages_gauge"(
                val.preimage.height, val.address.toString());

        foreach (stat; this.validator_preimages_stats.getStats())
            collector.collect(stat.value, stat.label);
    }

    /// Helper for stats
    private void recordBlockStats (in Block block) @safe
    {
        const new_count = this.ledger.enrollment_manager.validator_set.countActive(block.header.height + 1);
        this.block_stats.setMetricTo!"agora_block_height_counter"(
            block.header.height.value);
        this.block_stats.setMetricTo!"agora_block_enrollments_gauge"(new_count);
        this.block_stats.increaseMetricBy!"agora_block_txs_amount_total"(
            getUnspentAmount(block.txs));
        this.block_stats.increaseMetricBy!"agora_block_txs_total"(
            block.txs.length);
        this.block_stats.increaseMetricBy!"agora_block_externalized_total"(1);
        this.block_stats.setMetricTo!"agora_block_height_counter"(
            block.header.height.value);
    }

    /// Convenience function to increase an endpoint stats
    protected void recordReq (string endpoint, uint weight = 1) scope
        @safe pure nothrow
    {
        this.endpoint_request_stats.increaseMetricBy!"agora_endpoint_calls_total"(
            weight, endpoint, "http");
    }

    /***************************************************************************

        Begins asynchronous tasks for node discovery and periodic catchup.

    ***************************************************************************/

    public void start ()
    {
        if (config.node.stats_listening_port != 0)
            this.stats_server = this.makeStatsServer();
        this.transaction_relayer.start();

        // Special case
        // Block externalized handler is set and push for Genesis block.
        if (this.block_handlers.length > 0 && this.getBlockHeight() == 0)
            this.pushBlock(this.params.Genesis);

        this.timers ~= this.taskman.setTimer(
            this.config.node.network_discovery_interval, &this.discoveryTask, Periodic.Yes);
        this.timers ~= this.taskman.setTimer(
            this.config.node.block_catchup_interval, &this.catchupTask, Periodic.Yes);

        // Immediately run discovery to avoid delays at startup
        this.taskman.runTask(&this.discoveryTask);
    }

    /// Returns an already instantiated version of the BanManager
    /// (please also see `NetworkManager.getBanMananger()`)
    package BanManager getBanManager () @safe @nogc nothrow pure
    {
        return this.network.getBanManager();
    }

    /***************************************************************************

        Returns:
            the existing instance of the task manager

    ***************************************************************************/

    public ITaskManager getTaskManager () @safe @nogc nothrow pure
    {
        return this.taskman;
    }

    /***************************************************************************

        Returns:
            the existing instance of the network manager

    ***************************************************************************/

    public NetworkManager getNetworkManager () @safe @nogc nothrow pure
    {
        return this.network;
    }

    /***************************************************************************

        Returns:
            the existing instance of the execution engine

    ***************************************************************************/

    public Engine getEngine () @safe @nogc nothrow pure
    {
        return this.engine;
    }

    /***************************************************************************

        Periodically discovers new nodes in the network

    ***************************************************************************/

    protected void discoveryTask () nothrow
    {
        this.network.discover();
    }

    /***************************************************************************

        Periodically retrieve the latest blocks and apply them to the
        provided ledger.

        Params:
            ledger = the Ledger to apply received blocks to

    ***************************************************************************/

    protected void catchupTask () nothrow
    {
        if (this.network.peers.empty())  // no clients yet (discovery)
            return;

        this.network.getBlocksFrom(
            Height(this.ledger.getBlockHeight() + 1),
            &this.addBlocks);
        this.network.getUnknownTXs(this.ledger);
        try
        {
            this.network.getMissingBlockSigs(this.ledger).each!(h => pushBlockHeader(h));
        }
        catch (Exception e)
        {
            log.error("Error sending updated block headers:{}", e);
        }
    }

    /***************************************************************************

        Add blocks to the ledger and add the related pre-images

        This is called by the periodic catch-up process.

        Params:
            blocks = the blocks to be added
            preimages = the preimages needed to check the validity of the blocks

        Returns:
            the last read block height, or 0 if none were accepted

    ***************************************************************************/

    private Height addBlocks (const(Block)[] blocks, const(PreImageInfo)[] preimages)
        @safe
    {
        foreach (const ref block; blocks)
        {
            // ignore return value:
            // there's at least two cases where preimages will be rejected:
            // A) We already have a duplicate preimage
            // B) The preimage is for a newer enrollment which is in one of the
            //    `blocks` which we haven't read from yet
            this.ledger.enrollment_manager.addPreimages(preimages);
            // A block might have been externalized in the meantime,
            // so just skip older heights
            if (block.header.height <= this.ledger.getBlockHeight())
                continue;
            // Only add if we have at least half the signatures for this block
            else if (block.header.validators.setCount < block.header.validators.count / 2)
                continue;
            else if (!this.ledger.acceptBlock(block))
                break;
            this.recordBlockStats(block);
        }
        return this.ledger.getBlockHeight();
    }

    /***************************************************************************

        Function that is overriden in Validator to enable block signing during
            periodic catchup.

        Params:
            block = block to be added to the Ledger

    ***************************************************************************/

    protected bool acceptBlock (const ref Block block) @trusted
    {
        ExpiringValidator[] ex_validators;
        this.enroll_man.getExpiringValidators(block.header.height, ex_validators);
        // Attempt to add block to the ledger (it may be there by other means)
        if (this.ledger.acceptBlock(block))
        {
            this.recordBlockStats(block);
            ex_validators.each!(ex => this.network.unwhitelist(ex.utxo));
            this.ledger.getValidators(block.header.height)
                .each!(validator => this.network.whitelist(validator.utxo));
        }
        // We return if height in ledger is reached for this block to prevent fetching again
        return this.ledger.getBlockHeight() >= block.header.height;
    }

    /***************************************************************************

        Called on node shutdown.

        Note that this is called explicitly before any destructors,
        to allow clean shutdown of e.g. databases, which may require
        GC allocations during the shutdown phase.

    ***************************************************************************/

    public void shutdown () @safe
    {
        log.info("Shutting down..");
        foreach (timer; this.timers)
            timer.stop();

        this.taskman.logStats();
        this.network.shutdown();
        if (this.stats_server !is null)
            this.stats_server.shutdown();
        this.transaction_relayer.shutdown();
        this.pool = null;
        this.utxo_set = null;
        this.enroll_man = null;
        this.timers = null;
    }

    /// Make a new instance of the consensus parameters based on the config
    public static makeConsensusParams (in Config config)
    {
        import TESTNET = agora.consensus.data.genesis.Test;
        import COINNET = agora.consensus.data.genesis.Coinnet;

        auto commons_budget = config.node.testing ?
            TESTNET.CommonsBudgetAddress : COINNET.CommonsBudgetAddress;

        immutable Genesis = () {
            if (!config.node.testing)
                return COINNET.GenesisBlock;
            if (!config.node.limit_test_validators)
                return TESTNET.GenesisBlock;

            immutable Block result = {
                header: {
                    merkle_root: TESTNET.GenesisBlock.header.merkle_root,
                    time_offset: TESTNET.GenesisBlock.header.time_offset,
                    validators: typeof(BlockHeader.validators)(config.node.limit_test_validators),
                    enrollments: TESTNET.GenesisBlock.header.enrollments[0 .. config.node.limit_test_validators],
                },
                merkle_tree: TESTNET.GenesisBlock.merkle_tree,
                txs:         TESTNET.GenesisBlock.txs,
            };
            return result;
        }();

        return new immutable(ConsensusParams)(
                Genesis,
                commons_budget,
                config.consensus,
                config.node.block_interval_sec.seconds);
    }

    /// Returns a newly constructed StatsServer
    protected StatsServer makeStatsServer ()
    {
        return new StatsServer(this.config.node.stats_listening_port);
    }

    /// Returns: The Logger to use for this class
    protected Logger makeLogger ()
    {
        return Logger(__MODULE__);
    }

    /// Returns: A new instance of a `ManagedDatabase` to use as state DB
    protected ManagedDatabase makeStateDB ()
    {
        return new ManagedDatabase(this.config.node.data_dir.buildPath("state.db"));
    }

    /// Returns: A new instance of a `ManagedDatabase` to use as cache DB
    protected ManagedDatabase makeCacheDB ()
    {
        return new ManagedDatabase(this.config.node.data_dir.buildPath("cache.db"));
    }

    /***************************************************************************

        Returns an instance of a NetworkManager

        Unittests can override this method and return a custom NetworkManager.

        Params:
            node_config = the node config
            metadata = metadata containing known peers and other meta info
            taskman = task manager
            clock = clock instance

        Returns:
            an instance of a NetworkManager

    ***************************************************************************/

    protected NetworkManager makeNetworkManager (Metadata metadata,
        ITaskManager taskman, Clock clock)
    {
        return new NetworkManager(this.config, metadata, taskman, clock);
    }

    protected TransactionRelayer makeTransactionRelayer ()
    {
        return new TransactionRelayerFeeImp(this.pool, this.config, &this.network.peers,
            this.taskman, this.clock, &getAdjustedTXFee);
    }

    protected string getAdjustedTXFee (in Transaction tx, out Amount tot_fee) nothrow @safe
    {
        return this.fee_man.getAdjustedTXFee(tx, &this.utxo_set.peekUTXO, tot_fee);
    }

    /***************************************************************************

        Returns an instance of a TaskManager

        Subclasses can override this method and return
        a TaskManager backed by LocalRest.

        Returns:
            the task manager

    ***************************************************************************/

    protected ITaskManager makeTaskManager ()
    {
        return new VibeTaskManager();
    }

    /***************************************************************************

        Returns an instance of a Clock
        May be overriden in unittests to allow test-adjusted clock times.

        Params:
            taskman = a TaskManager instance

        Returns:
            an instance of a Clock

    ***************************************************************************/

    protected Clock makeClock (ITaskManager taskman)
    {
        // non-synchronizing clock (for now)
        return new Clock(
            (out long time_offset) { return true; },
            (Duration duration, void delegate() cb) nothrow @trusted
                { this.timers ~= this.taskman.setTimer(duration, cb, Periodic.Yes); });
    }

    /***************************************************************************

        Returns an instance of a TransactionPool

        Subclasses can override this method and return
        a TransactionPool backed by an in-memory SQLite database.

        Returns:
            the transaction pool

    ***************************************************************************/

    protected TransactionPool makeTransactionPool ()
    {
        return new TransactionPool(this.cacheDB, &getDoubleSpentSelector);
    }

    /***************************************************************************

        Returns an instance of a DoubleSpentSelector

        Subclasses can override this method and return
        a DoubleSpentSelector

        Returns:
            an instance of DoubleSpentSelector

    ***************************************************************************/

    protected size_t getDoubleSpentSelector (Transaction[] txs) nothrow @safe
    {
        return maxIndex!((a, b)
        {
            Amount fee_a;
            Amount fee_b;
            fee_man.getAdjustedTXFee(a, &this.utxo_set.peekUTXO, fee_a);
            fee_man.getAdjustedTXFee(b, &this.utxo_set.peekUTXO, fee_b);
            return fee_a < fee_b;
        }
        )(txs);
    }

    /***************************************************************************

        Returns an instance of a UTXOSet

        Unittest code may override this method to provide a Utxo set
        that doesn't do any I/O.

        Returns:
            the UTXOSet instance

    ***************************************************************************/

    protected UTXOSet makeUTXOSet ()
    {
        return new UTXOSet(this.stateDB);
    }

    /***************************************************************************

        Returns a new instance of a FeeManager

        Unittests can override this method.

        Returns:
            the FeeManager instance

    ***************************************************************************/

    protected FeeManager makeFeeManager ()
    {
        return new FeeManager(this.stateDB, this.params);
    }

    /***************************************************************************

        Reads the metadata from the provided disk path.

        Subclasses can override this method and return
        a Metadata object which loads/dumps data in memory
        rather than on disk, to avoid I/O (e.g. for unittesting)

        Returns:
            the metadata loaded from disk

    ***************************************************************************/

    protected Metadata makeMetadata () @system
    {
        return new DiskMetadata(this.config.node.data_dir);
    }

    /***************************************************************************

        Returns an instance of an `IBlockStorage`

        `IBlockStorage` is the object that handles the long-term storage
        of blocks. The base function returns an object that stores on disk,
        however derived classes may extend this to specify a different behavior.

        Returns:
            An instance of a `BlockStorage`

    ***************************************************************************/

    protected IBlockStorage makeBlockStorage () @system
    {
        return new BlockStorage(this.config.node.data_dir);
    }

    /***************************************************************************

        Returns an instance of a EnrollmentManager

        Returns:
            the enrollment manager

    ***************************************************************************/

    protected EnrollmentManager makeEnrollmentManager ()
    {
        return new EnrollmentManager(this.stateDB, this.cacheDB,
            this.config.validator.key_pair, this.params);
    }

    /*+*************************************************************************
    *                        FullNode API implementation                       *
    * The following methods are implementation of the API, which is exposed by *
    * our network interface generator (Vibe.d, Localrest) to expose interfaces.*
    * The network code generator will take care of the (de) marshalling of the *
    * parameter and the return value, so those methods can focus on            *
    * the business code.                                                       *
    ***************************************************************************/

    ///
    public override Identity handshake (PublicKey peer)
    {
        return Identity.init;
    }

    /***************************************************************************

        Register the given address as a listener for gossip / consensus messages.

        This register the given address into the `NetworkManager`.

        Params:
            address = the address of node to register

    ***************************************************************************/

    public void registerListener (Address address) @trusted
    {
        this.network.registerListener(address);
    }

    /// GET: /node_info
    public override NodeInfo getNodeInfo () nothrow @safe
    {
        this.recordReq("node_info");
        return this.network.getNetworkInfo();
    }

    /***************************************************************************

        Receive a transaction.

        API:
            PUT /transaction

        Params:
            tx = the received transaction

    ***************************************************************************/

    public override void putTransaction (Transaction tx) @safe
    {
        this.recordReq("transaction");
        auto tx_hash = hashFull(tx);
        if (this.pool.hasTransactionHash(tx_hash) ||
            !ledger.isAcceptableDoubleSpent(tx, config.node.double_spent_threshold_pct))
            return;

        this.tx_stats.increaseMetricBy!"agora_transactions_received_total"(1);
        if (!this.ledger.acceptTransaction(tx))
        {
            this.tx_stats.increaseMetricBy!"agora_transactions_rejected_total"(1);
            return;
        }

        log.info("Accepted transaction: {} ({})", prettify(tx), tx_hash);
        this.tx_stats.increaseMetricBy!"agora_transactions_accepted_total"(1);
        this.transaction_relayer.addTransaction(tx);
        this.pushTransaction(tx);
    }

    /// GET: /has_transaction_hash
    public override bool hasTransactionHash (Hash tx) @safe
    {
        this.recordReq("has_transaction_hash");
        return this.pool.hasTransactionHash(tx);
    }

    /// GET: /block_height
    public override ulong getBlockHeight ()
    {
        this.recordReq("block_heigth");
        return this.ledger.getBlockHeight();
    }

    /// GET: /blocks_from
    public override const(Block)[] getBlocksFrom (ulong height,
        uint max_blocks)  @safe
    {
        this.recordReq("blocks_from");
        return this.ledger.getBlocksFrom(Height(height))
            .take(min(max_blocks, MaxBatchBlocksSent)).array;
    }

    /// GET: /blocks/:height
    public override const(Block) getBlock (ulong height)  @safe
    {
        this.recordReq("blocks");

        auto blocks = this.ledger.getBlocksFrom(Height(height));
        if (blocks.empty)
            throw new HTTPStatusException(400, "No block at requested height");
        return blocks.front();
    }

    /// GET: /merkle_path
    public override Hash[] getMerklePath (ulong height, Hash hash) @safe
    {
        this.recordReq("merkle_path");

        const Height stored_height = Height(height);

        if (this.ledger.getBlockHeight() < stored_height)
            return null;

        Block block = this.storage.readBlock(stored_height);
        size_t index = block.findHashIndex(hash);
        if (index >= block.txs.length)
            return null;
        return block.getMerklePath(index);
    }

    /// PUT: /enroll_validator
    public override void enrollValidator (Enrollment enroll) @safe
    {
        this.recordReq("enroll_validator");

        UTXO utxo;
        this.utxo_set.peekUTXO(enroll.utxo_key, utxo);
        const utxo_address = utxo.output.address;
        if (this.enroll_man.addEnrollment(enroll, utxo_address,
            this.ledger.getBlockHeight() + 1, this.utxo_set.getUTXOFinder()))
        {
            log.info("Accepted enrollment: {}", prettify(enroll));
            this.network.peers.each!(p => p.client.sendEnrollment(enroll));
        }
    }

    /// GET: /enrollment
    public override Enrollment getEnrollment (Hash enroll_hash) @safe
    {
        this.recordReq("enrollment");
        return this.enroll_man.getEnrollment(enroll_hash);
    }

    /// PUT: /receive_preimage
    public override void receivePreimage (PreImageInfo preimage) @safe
    {
        this.recordReq("receive_preimage");
        log.trace("Received Preimage: {}", prettify(preimage));

        if (this.enroll_man.addPreimage(preimage))
        {
            log.info("Accepted preimage: {}", prettify(preimage));
            this.network.peers.each!(p => p.client.sendPreimage(preimage));
            this.pushPreImage(preimage);
        }
    }

    /// GET: /preimages_for_enroll_keys
    public override PreImageInfo[] getPreimagesForEnrollKeys (Set!Hash enroll_keys = Set!Hash.init) @safe nothrow
    {
        this.recordReq("preimages_for_enroll_keys");

        // if enroll_keys is empty, then all preimages should be returned
        if (enroll_keys.empty())
        {
            Hash[] utxos;
            if (this.enroll_man.validator_set.getEnrolledUTXOs(Height(ledger.getBlockHeight + 1), utxos))
                foreach (const ref utxo; utxos)
                    enroll_keys.put(utxo);
        }

        PreImageInfo[] preimage_infos;
        foreach (const enroll_key; enroll_keys)
        {
            auto preimage_info = this.enroll_man.getValidatorPreimage(enroll_key);
            if (preimage_info != PreImageInfo.init)
                preimage_infos ~= preimage_info;
        }

        return preimage_infos;
    }

    /// GET: /preimages
    public override PreImageInfo[] getPreimages (ulong start_height,
        ulong end_height) @safe nothrow
    {
        this.recordReq("preimages");
        return this.enroll_man.getValidatorPreimages(Height(start_height),
            Height(end_height)).array();
    }

    /// GET /local_time
    public override TimePoint getLocalTime () @safe nothrow
    {
        this.recordReq("local_time");
        return this.clock.localTime();
    }

    /***************************************************************************

        Called when a block was externalized.

        Calls pushBlock(), but additionally the Validator overrides this
        and implements quorum shuffling.

        Params:
            block = the new block
            validators_changed = whether the validator set has changed

    ***************************************************************************/

    protected void onAcceptedBlock (in Block block, bool validators_changed)
        @safe
    {
        this.pushBlock(block);
    }

    /***************************************************************************

        Push the block data to the `block_handlers` target server list
        set in config.

        Convert block data to JSON serialization and send it POST using Rest.

        Params:
            block = externalized block data

    ***************************************************************************/

    private void pushBlock (const Block block) @trusted
    {
        foreach (address, handler; this.block_handlers)
        {
            this.taskman.runTask({
                try
                {
                    handler.pushBlock(block);
                }
                catch (Exception e)
                {
                    log.error("Error sending block height #{} to {} :{}",
                        block.header.height, address, e);
                }
            });
        }
    }

    /***************************************************************************

        Push an updated block header to the `blockheader_handlers` target server
        list set in config.
        The blockheader can have signatures from validators added even after the
        block has been externalized.

        Convert block header data to JSON serialization and send it POST using
        Rest.

        Params:
            header = updated block header data

    ***************************************************************************/

    private void pushBlockHeader (const BlockHeader header) @trusted
    {
        foreach (address, handler; this.block_header_handlers)
        {
            this.taskman.runTask({
                try
                {
                    handler.pushBlockHeader(header);
                }
                catch (Exception e)
                {
                    log.error("Error sending block header at height #{} to {} :{}",
                        header.height, address, e);
                }
            });
        }
    }

    /***************************************************************************

        Push the preimage to the `preimage_handlers` target server list
        set in config.

        Convert `PreImageInfo` to JSON serialization and send it POST
        using Rest.

        Params:
            preImage = Received `PreImageInfo`

    ***************************************************************************/

    protected void pushPreImage (const PreImageInfo pre_image) @trusted
    {
        foreach (address, handler; this.preimage_handlers)
        {
            this.taskman.runTask({
                try
                {
                    handler.pushPreImage(pre_image);
                }
                catch (Exception e)
                {
                    log.error("Error sending preImage (enroll_key: {}) to {} :{}",
                        pre_image.utxo, address, e);
                }
            });
        }
    }

    /***************************************************************************

        Push the transaction to the `transaction_handlers` target server list
        set in config.

        Convert `Transaction` to JSON serialization and send it POST using Rest.

        Params:
            tx = Received `Transaction`

    ***************************************************************************/

    protected void pushTransaction (const Transaction tx) @trusted
    {
        foreach (address, handler; this.transaction_handlers)
        {
            this.taskman.runTask({
                try
                {
                    handler.pushTransaction(tx);
                }
                catch (Exception e)
                {
                    log.error("Error sending transaction (tx hash: {}) to {} :{}",
                        hashFull(tx), address, e);
                }
            });
        }
    }

    /***************************************************************************

        Params:
            tx_hashes = A Set of Transaction hashes

        Returns:
            Transactions, if found in the pool, corresponding to the
            requested hashes

    ***************************************************************************/

    public Transaction[] getTransactions (Set!Hash tx_hashes) @safe
    {
        this.recordReq("transactions");

        Transaction[] found_txs;
        foreach (hash; tx_hashes)
        {
            if (found_txs.length >= MaxBatchTranscationsSent)
                break;
            auto tx = this.pool.getTransactionByHash(hash);
            if (tx != Transaction.init)
                found_txs ~= tx;
        }
        return found_txs;
    }

    /***************************************************************************

        Params:
            heights = Set of block Heights to return header for

        Returns:
            BlockHeader if the client has that block

    ***************************************************************************/

    public BlockHeader[] getBlockHeaders (Set!ulong heights) @safe
    {
        import std.algorithm: min;
        import std.conv;

        this.recordReq("block_headers");
        BlockHeader[] headers;
        if (!heights.empty)
        {
            foreach (block; this.ledger.getBlocksFrom(Height(heights[].minElement)))
            {
                if (block.header.height in heights)
                    headers ~= block.header;
            }
        }
        return headers;
    }

    ///
    public ValidatorInfo[] getValidators (ulong height)
    {
        this.recordReq("validators");
        return this.ledger.getValidators(Height(height));
    }

    ///
    public ValidatorInfo[] getValidators ()
    {
        return this.getValidators(this.ledger.getBlockHeight());
    }
}
