/*******************************************************************************

    Contains Flash layer tests.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.Flash;

version (unittest):

import agora.api.FullNode : FullNodeAPI = API;
import agora.common.Amount;
import agora.common.Config;
import agora.common.ManagedDatabase;
import agora.common.Types;
import agora.common.Task;
import agora.consensus.data.genesis.Test;
import agora.consensus.data.Transaction;
import agora.consensus.data.UTXO;
import agora.crypto.ECC;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.crypto.Schnorr;
import agora.flash.api.FlashAPI;
import agora.flash.api.FlashControlAPI;
import agora.flash.api.FlashListenerAPI;
import agora.flash.Channel;
import agora.flash.Config;
import agora.flash.ErrorCode;
import agora.flash.Invoice;
import agora.flash.Node;
import agora.flash.OnionPacket;
import agora.flash.Route;
import agora.flash.Scripts;
import agora.flash.Types;
import agora.script.Engine;
import agora.script.Lock;
import agora.script.Script;
import agora.serialization.Serializer;
import agora.test.Base;
import agora.utils.Log;

import geod24.LocalRest : Listener;
import geod24.Registry;

import std.algorithm;
import std.conv;
import std.exception;

import core.stdc.time;
import core.time;
import core.thread;

mixin AddLogger!();

/// Listener (wallet / front-end)
public interface TestFlashListenerAPI : FlashListenerAPI
{
    /// wait until we get a signal that the payment for this invoice
    /// has succeeded / failed, and return true / false for success
    ErrorCode waitUntilNotified (Invoice);

    /// wait until we get a notification about the given channel state,
    /// and return any associated error codes
    ErrorCode waitUntilChannelState (Hash, ChannelState, PublicKey node = PublicKey.init);
}

/// In addition to the Flash APIs, we provide methods for conditional waits
/// and extracting update / closing / settle pairs, and forceful channel close.
public interface TestFlashAPI : FlashControlAPI
{
    /// Wait for the specified update index. Index 0 is the funding state.
    /// Note that a payment also triggers an update later when the secret
    /// is revealed, so the indexes passed are usually even numbers (2, 4, 6..)
    public void waitForUpdateIndex (in PublicKey pk, in Hash chan_id,
        in uint index);

    /// Wait until the specified channel ID has been gossiped to this node
    public void waitForChannelDiscovery (in Hash chan_id);

    /// Wait until the specified channel ID has been opened. The node must be
    /// part of this channel.
    public void waitForChannelOpen (in PublicKey pk, in Hash chan_id);

    /// Wait until the specified channel update has been gossiped to this node
    public ChannelUpdate waitForChannelUpdate (in Hash chan_id,
        in PaymentDirection dir, in uint update_idx);

    /// Force publishing an update tx with the given index to the blockchain.
    /// Used for testing and ensuring the counter-party detects the update tx
    /// and publishes the latest state to the blockchain.
    public Transaction getPublishUpdateIndex (in PublicKey pk, in Hash chan_id,
        in uint index);

    /// Get the expected closing tx that should have been published to the chain
    public Transaction getClosingTx (in PublicKey pk, in Hash chan_id);

    /// Get the expected settlement tx when a trigger was published to the chain
    public Transaction getLastSettleTx (in PublicKey pk, in Hash chan_id);

    /// Print out the contents of the log
    public abstract void printLog ();

    /// Shut down any timers (forwards to ThinFlashNode.shutdown)
    public void shutdownNode ();
}

/// Controls behavior of database storage for the Flash layer
enum DatabaseStorage : string
{
    /// db erased between restarts
    Local = ":memory:",

    /// db preserved between restarts
    Static = ":static:",
}

/// A thin localrest flash node which itself is not a FullNode / Validator
public class TestFlashNode : ThinFlashNode, TestFlashAPI
{
    ///
    protected Registry!TestAPI* agora_registry;

    ///
    protected Registry!TestFlashAPI* flash_registry;

    ///
    protected Registry!TestFlashListenerAPI* listener_registry;

    ///
    public this (FlashConfig conf, Registry!TestAPI* agora_registry,
        string agora_address, DatabaseStorage storage,
        Registry!TestFlashAPI* flash_registry,
        Registry!TestFlashListenerAPI* listener_registry)
    {
        this.agora_registry = agora_registry;
        this.flash_registry = flash_registry;
        this.listener_registry = listener_registry;
        const genesis_hash = hashFull(GenesisBlock);
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        auto engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        super(conf, storage, genesis_hash, engine, new LocalRestTaskManager(),
            agora_address);
    }

    /***************************************************************************

        Get either a managed database local to the class, or a static one
        which will survive restarts.

        Params:
            db_path = path to the database

        Returns:
            a ManagedDatabase instance for the given path

    ***************************************************************************/

    protected override ManagedDatabase getManagedDatabase (string db_path)
    {
        if (db_path == DatabaseStorage.Static)
        {
            static ManagedDatabase static_db;
            if (static_db is null)
                static_db = new ManagedDatabase(":memory:");
            return static_db;
        }

        return new ManagedDatabase(db_path);
    }

    ///
    public override void shutdownNode ()
    {
        log.info("Shutting down node!");
        super.shutdown();  // kill timers
    }

    ///
    protected override FullNodeAPI getAgoraClient (Address address,
        Duration timeout)
    {
        auto tid = this.agora_registry.locate(address);
        assert(tid != typeof(tid).init, "Agora node not initialized");
        return new RemoteAPI!TestAPI(tid, timeout);
    }

    ///
    protected override TestFlashAPI getFlashClient (in PublicKey peer_pk,
        Duration timeout) @trusted
    {
        if (auto peer = peer_pk in this.known_peers)
        {
            auto control_api = cast(TestFlashAPI)*peer;
            assert(control_api !is null);  // something's wrong
            return control_api;
        }

        // give some time to the other node to wake up and register
        Listener!TestFlashAPI tid;
        foreach (i; 0 .. 5)
        {
            tid = this.flash_registry.locate(peer_pk.to!string);
            if (tid != typeof(tid).init)
                break;

            this.taskman.wait(500.msecs);
        }

        assert(tid != typeof(tid).init, "Flash node not initialized");

        auto peer = new RemoteAPI!TestFlashAPI(tid, timeout);
        this.known_peers[peer_pk] = peer;
        if (this.known_channels.length > 0)
        {
            peer.gossipChannelsOpen(this.known_channels.values);
            peer.gossipChannelUpdates(this.channel_updates.byValue
                .map!(updates => updates.byValue).joiner.array);
        }

        return peer;
    }

    protected override TestFlashListenerAPI getFlashListenerClient (
        string address, Duration timeout) @trusted
    {
        auto tid = this.listener_registry.locate(address);
        assert(tid != typeof(tid).init);
        return new RemoteAPI!TestFlashListenerAPI(tid, timeout);
    }

    ///
    public override Transaction getPublishUpdateIndex (in PublicKey pk,
        in Hash chan_id, in uint index)
    {
        auto channel = chan_id in this.channels[pk];
        assert(channel !is null);
        return channel.getPublishUpdateIndex(index);
    }

    ///
    public override void waitForUpdateIndex (in PublicKey pk, in Hash chan_id,
        in uint index)
    {
        auto channel = chan_id in this.channels[pk];
        assert(channel !is null);
        return channel.waitForUpdateIndex(index);
    }

    ///
    public override void waitForChannelDiscovery (in Hash chan_id)
    {
        // Wait for discovery and first set of updates
        while (chan_id !in this.known_channels ||
                chan_id !in this.channel_updates ||
                this.channel_updates[chan_id].length < 2)
            this.taskman.wait(100.msecs);
    }

    ///
    public override void waitForChannelOpen (in PublicKey pk, in Hash chan_id)
    {
        super.waitChannelOpen(pk, chan_id);
    }

    ///
    public override ChannelUpdate waitForChannelUpdate (in Hash chan_id,
        in PaymentDirection dir, in uint update_idx)
    {
        while (1)
        {
            if (auto updates = chan_id in this.channel_updates)
                if (auto update = dir in *updates)
                    if (update.update_idx == update_idx)
                        return *update;

            this.taskman.wait(100.msecs);
        }
    }

    ///
    public override Transaction getClosingTx (in PublicKey pk, in Hash chan_id)
    {
        auto channel = chan_id in this.channels[pk];
        assert(channel !is null);
        return channel.getClosingTx();
    }

    ///
    public override Transaction getLastSettleTx (in PublicKey pk, in Hash chan_id)
    {
        auto channel = chan_id in this.channels[pk];
        assert(channel !is null);
        return channel.getLastSettleTx();
    }

    /// Prints out the log contents for this node
    public void printLog ()
    {
        auto output = stdout.lockingTextWriter();
        output.formattedWrite("Log for Flash node %s:\n", cast(void*)this);
        output.put("======================================================================\n");
        CircularAppender!()().print(output);
        output.put("======================================================================\n\n");
        stdout.flush();
    }
}

/// Is in charge of spawning the flash nodes
public class FlashNodeFactory (FlashListenerType = FlashListener)
{
    /// Registry of nodes
    private Registry!TestAPI* agora_registry;

    /// we keep a separate LocalRest registry of the flash "nodes"
    private Registry!TestFlashAPI flash_registry;

    /// and a registry of listener nodes (usually just one)
    private Registry!TestFlashListenerAPI listener_registry;

    /// list of flash addresses
    private PublicKey[] addresses;

    /// list of listener addresses
    private string[] listener_addresses;

    /// list of flash nodes
    private RemoteAPI!TestFlashAPI[] nodes;

    /// list of FlashListenerAPI nodes
    private RemoteAPI!TestFlashListenerAPI[] listener_nodes;

    /// Flash listener address
    private static const ListenerAddress = "flash-listener";

    /// Flash listener (Wallet)
    public TestFlashListenerAPI listener;

    /// Ctor
    public this (Registry!TestAPI* agora_registry)
    {
        this.agora_registry = agora_registry;
        this.flash_registry.initialize();
        this.listener_registry.initialize();

        this.listener = this.createFlashListener!FlashListenerType(
            ListenerAddress);
    }

    /// Create a new flash node user
    public RemoteAPI!TestFlashAPI create (FlashNodeImpl = TestFlashNode)
        (const Pair pair, string agora_address,
         DatabaseStorage storage = DatabaseStorage.Local)
    {
        FlashConfig conf = { enabled : true,
            min_funding : Amount(1000),
            max_funding : Amount(100_000_000),
            min_settle_time : 0,
            max_settle_time : 100,
            max_retry_time : 4.seconds,
            max_retry_delay : 100.msecs,
            listener_address : ListenerAddress, };
        return this.create!FlashNodeImpl(pair, conf, agora_address, storage);
    }

    /// ditto
    public RemoteAPI!TestFlashAPI create (FlashNodeImpl = TestFlashNode)
        (const Pair pair, FlashConfig conf, string agora_address,
         DatabaseStorage storage = DatabaseStorage.Local)
    {
        RemoteAPI!TestFlashAPI api = RemoteAPI!TestFlashAPI.spawn!FlashNodeImpl(
            conf, this.agora_registry, agora_address, storage,
            &this.flash_registry, &this.listener_registry,
            10.seconds);  // timeout from main thread

        auto pk = PublicKey(pair.V);
        this.addresses ~= pk;
        this.nodes ~= api;
        this.flash_registry.register(pk.to!string, api.listener());
        api.start();
        const key_pair = KeyPair(pk, SecretKey(pair.v));
        api.registerKey(key_pair.secret);

        return api;
    }

    /// Create a new FlashListenerAPI node
    public RemoteAPI!TestFlashListenerAPI createFlashListener (
        Listener : TestFlashListenerAPI)(string address)
    {
        RemoteAPI!TestFlashListenerAPI api
            = RemoteAPI!TestFlashListenerAPI.spawn!Listener(5.seconds);
        this.listener_registry.register(address, api.listener());
        this.listener_addresses ~= address;
        this.listener_nodes ~= api;
        return api;
    }

    /***************************************************************************

        Print out the logs for each node

    ***************************************************************************/

    public void printLogs (string file = __FILE__, int line = __LINE__)
    {
        if (no_logs)
            return;

        synchronized  // make sure logging output is not interleaved
        {
            writeln("---------------------------- START OF LOGS ----------------------------");
            writefln("%s(%s): Flash node logs:\n", file, line);
            foreach (node; this.nodes)
            {
                try
                {
                    node.printLog();
                }
                catch (Exception ex)
                {
                    writefln("Could not print logs for node: %s", ex.message);
                }
            }
        }

        auto output = stdout.lockingTextWriter();
        output.put("Flash log for tests\n");
        output.put("======================================================================\n");
        CircularAppender!()().print(output);
        output.put("======================================================================\n\n");
        stdout.flush();
    }

    /// Shut down all the nodes
    public void shutdown ()
    {
        foreach (address; this.addresses)
            enforce(this.flash_registry.unregister(address.to!string));

        foreach (address; this.listener_addresses)
            enforce(this.listener_registry.unregister(address));

        foreach (node; this.nodes)
            node.shutdownNode();

        foreach (node; this.nodes)
            node.ctrl.shutdown();

        foreach (node; this.listener_nodes)
        {
            node.ctrl.shutdown();
        }
    }

    /// Shut down & restart all nodes
    public void restart ()
    {
        foreach (node; this.nodes)
        {
            node.ctrl.restart((Object node) { (cast(TestFlashNode)node).shutdownNode(); });
            node.ctrl.withTimeout(0.msecs, (scope FlashControlAPI api) { api.start(); });
        }
    }
}

/// Listens for Flash events (if registered with a Flash node)
private class FlashListener : TestFlashListenerAPI
{
    static struct State
    {
        ChannelState state;
        ErrorCode error;
    }

    State[PublicKey][Hash] channel_state;
    ErrorCode[Invoice] invoices;
    LocalRestTaskManager taskman;

    public this ()
    {
        this.taskman = new LocalRestTaskManager();
    }

    public void onPaymentSuccess (PublicKey pk, Invoice invoice)
    {
        this.invoices[invoice] = ErrorCode.None;
    }

    public void onPaymentFailure (PublicKey pk, Invoice invoice, ErrorCode error)
    {
        this.invoices[invoice] = error;
    }

    public ErrorCode waitUntilNotified (Invoice invoice)
    {
        while (1)
        {
            if (auto inv = invoice in this.invoices)
            {
                scope (exit) this.invoices.remove(invoice);
                return *inv;
            }

            this.taskman.wait(200.msecs);
        }
    }

    public ErrorCode waitUntilChannelState (Hash chan_id, ChannelState state,
        PublicKey node = PublicKey.init)
    {
        scope (exit) this.channel_state.remove(chan_id);
        while (1)
        {
            if (auto chan_states = chan_id in this.channel_state)
            {
                if (auto chan_state = node in *chan_states)
                    if ((*chan_state).state >= state)
                        return (*chan_state).error;
                if (node == PublicKey.init)
                {
                    auto states = chan_states.byValue
                        .filter!(chan_state => chan_state.state >= state);
                    if (!states.empty())
                        return states.front.error;
                }
            }

            this.taskman.wait(200.msecs);
        }
    }

    public void onChannelNotify (PublicKey pk, Hash chan_id, ChannelState state,
        ErrorCode error)
    {
        if (chan_id !in this.channel_state)
            this.channel_state[chan_id] = typeof(this.channel_state[chan_id]).init;
        this.channel_state[chan_id][pk] = State(state, error);
    }

    public string onRequestedChannelOpen (PublicKey pk, ChannelConfig conf)
    {
        return null;  // accept by default
    }

    public FeeUTXOs getFeeUTXOs (PublicKey pk, Amount amount)
    {
        assert(0);
    }

    public Amount getEstimatedTxFee ()
    {
        return Amount(1);
    }
}

/// Test unilateral non-collaborative close (funding + update* + settle)
//version (none)
unittest
{
    TestConf conf = { payout_period : 100 };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];
    scope (failure) node_1.printLog();

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();

    foreach (idx, tx; txs)
    {
        node_1.putTransaction(tx);
        network.expectHeightAndPreImg(Height(idx + 1), network.blocks[0].header);
    }

    auto factory = new FlashNodeFactory!()(network.getRegistry());
    scope (exit) factory.shutdown();
    scope (failure) factory.printLogs();

    const alice_pair = Pair(WK.Keys[0].secret, WK.Keys[0].secret.toPoint);
    const bob_pair = Pair(WK.Keys[1].secret, WK.Keys[1].secret.toPoint);

    // workaround to get a handle to the node from another registry's thread
    const string address = format("Validator #%s (%s)", 0, genesis_validator_keys[0].address);
    auto alice = factory.create(alice_pair, address);
    auto bob = factory.create(bob_pair, address);
    const alice_pk = PublicKey(alice_pair.V);
    const bob_pk = PublicKey(bob_pair.V);

    // 0 blocks settle time after trigger tx is published (unsafe)
    const Settle_1_Blocks = 0;
    //const Settle_10_Blocks = 10;

    // the utxo the funding tx will spend (only relevant to the funder)
    const utxo = UTXO(0, txs[0].outputs[0]);
    const utxo_hash = UTXO.getHash(hashFull(txs[0]), 0);
    const chan_id_res = alice.openNewChannel(alice_pk,
        utxo, utxo_hash, Amount(10_000), Settle_1_Blocks, bob_pair.V);
    assert(chan_id_res.error == ErrorCode.None, chan_id_res.message);
    const chan_id = chan_id_res.value;
    factory.listener.waitUntilChannelState(chan_id, ChannelState.SettingUp);

    // await funding transaction
    network.expectHeightAndPreImg(Height(9), network.blocks[0].header);
    const block_9 = node_1.getBlocksFrom(9, 1)[$ - 1];
    assert(block_9.txs.any!(tx => tx.hashFull() == chan_id));

    // wait for the parties & listener to detect the funding tx
    alice.waitForChannelOpen(alice_pk, chan_id);
    bob.waitForChannelOpen(bob_pk, chan_id);
    factory.listener.waitUntilChannelState(chan_id, ChannelState.Open);

    auto update_tx = alice.getPublishUpdateIndex(alice_pk, chan_id, 0);

    /* do some off-chain transactions */
    auto inv_1 = bob.createNewInvoice(bob_pk, Amount(5_000), time_t.max, "payment 1");
    alice.payInvoice(alice_pk, inv_1.value);

    alice.waitForUpdateIndex(alice_pk, chan_id, 2);
    bob.waitForUpdateIndex(bob_pk, chan_id, 2);

    auto inv_2 = bob.createNewInvoice(bob_pk, Amount(1_000), time_t.max, "payment 2");
    alice.payInvoice(alice_pk, inv_2.value);

    // need to wait for invoices to be complete before we have the new balance
    // to send in the other direction
    alice.waitForUpdateIndex(alice_pk, chan_id, 4);
    bob.waitForUpdateIndex(bob_pk, chan_id, 4);

    // note the reverse payment from bob to alice. Can use this for refunds too.
    auto inv_3 = alice.createNewInvoice(alice_pk, Amount(2_000), time_t.max, "payment 3");
    bob.payInvoice(bob_pk, inv_3.value);

    alice.waitForUpdateIndex(alice_pk, chan_id, 6);
    bob.waitForUpdateIndex(bob_pk, chan_id, 6);

    // alice is acting bad
    log.info("Alice unilaterally closing the channel..");
    network.expectHeightAndPreImg(Height(10), network.blocks[0].header);
    auto tx_10 = node_1.getBlocksFrom(10, 1)[0].txs[0];
    assert(tx_10 == update_tx);
    factory.listener.waitUntilChannelState(chan_id,
        ChannelState.StartedUnilateralClose);

    // at this point bob will automatically publish the latest update tx
    network.expectHeightAndPreImg(Height(11), network.blocks[0].header);

    // and then a settlement will be published (but only after time lock expires)
    auto settle_tx = bob.getLastSettleTx(bob_pk, chan_id);
    network.expectHeightAndPreImg(Height(12), network.blocks[0].header);
    auto tx_12 = node_1.getBlocksFrom(12, 1)[0].txs[0];
    factory.listener.waitUntilChannelState(chan_id, ChannelState.Closed);
    //assert(tx_12 == settle_tx);
}

/// Test the settlement timeout branch for the
/// unilateral non-collaborative close (funding + update* + settle)
//version (none)
unittest
{
    TestConf conf = { payout_period : 100 };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];
    scope (failure) node_1.printLog();

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();

    foreach (idx, tx; txs[0 .. 4])
    {
        node_1.putTransaction(tx);
        network.expectHeightAndPreImg(Height(idx + 1), network.blocks[0].header);
    }

    auto factory = new FlashNodeFactory!()(network.getRegistry());
    scope (exit) factory.shutdown();
    scope (failure) factory.printLogs();

    const alice_pair = Pair(WK.Keys[0].secret, WK.Keys[0].secret.toPoint);
    const bob_pair = Pair(WK.Keys[1].secret, WK.Keys[1].secret.toPoint);

    // workaround to get a handle to the node from another registry's thread
    const string address = format("Validator #%s (%s)", 0, genesis_validator_keys[0].address);
    auto alice = factory.create(alice_pair, address);
    auto bob = factory.create(bob_pair, address);
    const alice_pk = PublicKey(alice_pair.V);
    const bob_pk = PublicKey(bob_pair.V);

    // 4 blocks settle time after trigger tx is published
    const Settle_4_Blocks = 4;

    // the utxo the funding tx will spend (only relevant to the funder)
    const utxo = UTXO(0, txs[0].outputs[0]);
    const utxo_hash = UTXO.getHash(hashFull(txs[0]), 0);
    const chan_id_res = alice.openNewChannel(alice_pk,
        utxo, utxo_hash, Amount(10_000), Settle_4_Blocks, bob_pair.V);
    assert(chan_id_res.error == ErrorCode.None, chan_id_res.message);
    const chan_id = chan_id_res.value;
    factory.listener.waitUntilChannelState(chan_id, ChannelState.SettingUp);

    // await funding transaction
    network.expectHeightAndPreImg(Height(5), network.blocks[0].header);
    const block_9 = node_1.getBlocksFrom(5, 1)[$ - 1];
    assert(block_9.txs.any!(tx => tx.hashFull() == chan_id));

    // wait for the parties & listener to detect the funding tx
    alice.waitForChannelOpen(alice_pk, chan_id);
    bob.waitForChannelOpen(bob_pk, chan_id);
    factory.listener.waitUntilChannelState(chan_id, ChannelState.Open);

    auto update_tx = alice.getPublishUpdateIndex(alice_pk, chan_id, 0);

    /* do some off-chain transactions */
    auto inv_1 = bob.createNewInvoice(bob_pk, Amount(5_000), time_t.max,
        "payment 1");
    alice.payInvoice(alice_pk, inv_1.value);

    alice.waitForUpdateIndex(alice_pk, chan_id, 2);
    bob.waitForUpdateIndex(bob_pk, chan_id, 2);

    auto inv_2 = bob.createNewInvoice(bob_pk, Amount(1_000), time_t.max,
        "payment 2");
    alice.payInvoice(alice_pk, inv_2.value);

    // need to wait for invoices to be complete before we have the new balance
    // to send in the other direction
    alice.waitForUpdateIndex(alice_pk, chan_id, 4);
    bob.waitForUpdateIndex(bob_pk, chan_id, 4);

    // note the reverse payment from bob to alice. Can use this for refunds too.
    auto inv_3 = alice.createNewInvoice(alice_pk, Amount(2_000), time_t.max,
        "payment 3");
    bob.payInvoice(bob_pk, inv_3.value);

    alice.waitForUpdateIndex(alice_pk, chan_id, 6);
    bob.waitForUpdateIndex(bob_pk, chan_id, 6);

    // alice is acting bad
    log.info("Alice unilaterally closing the channel..");
    network.expectHeightAndPreImg(Height(6), network.blocks[0].header);
    auto tx_10 = node_1.getBlocksFrom(6, 1)[0].txs[0];
    assert(tx_10 == update_tx);
    factory.listener.waitUntilChannelState(chan_id,
        ChannelState.StartedUnilateralClose);

    // at this point bob will automatically publish the latest update tx
    network.expectHeightAndPreImg(Height(7), network.blocks[0].header);

    // at `Settle_4_Blocks` blocks need to be externalized before a settlement
    // can be attached to the update transaction
    node_1.putTransaction(txs[4]);
    network.expectHeightAndPreImg(Height(8), network.blocks[0].header);
    node_1.putTransaction(txs[5]);
    network.expectHeightAndPreImg(Height(9), network.blocks[0].header);
    node_1.putTransaction(txs[6]);
    network.expectHeightAndPreImg(Height(10), network.blocks[0].header);
    node_1.putTransaction(txs[7]);
    network.expectHeightAndPreImg(Height(11), network.blocks[0].header);

    // and then a settlement will be automatically published
    auto settle_tx = bob.getLastSettleTx(bob_pk, chan_id);
    network.expectHeightAndPreImg(Height(12), network.blocks[0].header);
    auto tx_12 = node_1.getBlocksFrom(12, 1)[0].txs[0];
    factory.listener.waitUntilChannelState(chan_id, ChannelState.Closed);
    assert(tx_12 == settle_tx);
}

/// Test attempted collaborative close with a non-collaborative counter-party,
/// forcing the first counter-party to initiate a non-collaborative close.
//version (none)
unittest
{
    static class RejectingCloseNode : TestFlashNode
    {
        mixin ForwardCtor!();

        ///
        protected override Result!Point closeChannel (PublicKey sender_pk,
            PublicKey pk, Hash chan_id, uint seq_id, Point peer_nonce,
            Amount fee)
        {
            return Result!Point(ErrorCode.Unknown);
        }
    }

    TestConf conf = { payout_period : 100 };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];
    scope (failure) node_1.printLog();

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();

    foreach (idx, tx; txs)
    {
        node_1.putTransaction(tx);
        network.expectHeightAndPreImg(Height(idx + 1), network.blocks[0].header);
    }

    auto factory = new FlashNodeFactory!()(network.getRegistry());
    scope (exit) factory.shutdown();
    scope (failure) factory.printLogs();

    const alice_pair = Pair(WK.Keys[0].secret, WK.Keys[0].secret.toPoint);
    const bob_pair = Pair(WK.Keys[1].secret, WK.Keys[1].secret.toPoint);

    // workaround to get a handle to the node from another registry's thread
    const string address = format("Validator #%s (%s)", 0, genesis_validator_keys[0].address);
    auto alice = factory.create(alice_pair, address);
    auto bob = factory.create!RejectingCloseNode(bob_pair, address);
    const alice_pk = PublicKey(alice_pair.V);
    const bob_pk = PublicKey(bob_pair.V);

    // 0 blocks settle time after trigger tx is published (unsafe)
    const Settle_1_Blocks = 0;
    //const Settle_10_Blocks = 10;

    // the utxo the funding tx will spend (only relevant to the funder)
    const utxo = UTXO(0, txs[0].outputs[0]);
    const utxo_hash = UTXO.getHash(hashFull(txs[0]), 0);
    const chan_id_res = alice.openNewChannel(alice_pk,
        utxo, utxo_hash, Amount(10_000), Settle_1_Blocks, bob_pair.V);
    assert(chan_id_res.error == ErrorCode.None, chan_id_res.message);
    const chan_id = chan_id_res.value;
    factory.listener.waitUntilChannelState(chan_id, ChannelState.SettingUp);

    // await funding transaction
    network.expectHeightAndPreImg(Height(9), network.blocks[0].header);
    const block_9 = node_1.getBlocksFrom(9, 1)[$ - 1];
    assert(block_9.txs.any!(tx => tx.hashFull() == chan_id));

    // wait for the parties & listener to detect the funding tx
    alice.waitForChannelOpen(alice_pk, chan_id);
    bob.waitForChannelOpen(bob_pk, chan_id);
    factory.listener.waitUntilChannelState(chan_id, ChannelState.Open);

    /* do some off-chain transactions */
    auto inv_1 = bob.createNewInvoice(bob_pk, Amount(5_000), time_t.max, "payment 1");
    alice.payInvoice(alice_pk, inv_1.value);

    alice.waitForUpdateIndex(alice_pk, chan_id, 2);
    bob.waitForUpdateIndex(bob_pk, chan_id, 2);

    auto inv_2 = bob.createNewInvoice(bob_pk, Amount(1_000), time_t.max, "payment 2");
    alice.payInvoice(alice_pk, inv_2.value);

    // need to wait for invoices to be complete before we have the new balance
    // to send in the other direction
    alice.waitForUpdateIndex(alice_pk, chan_id, 4);
    bob.waitForUpdateIndex(bob_pk, chan_id, 4);

    // note the reverse payment from bob to alice. Can use this for refunds too.
    auto inv_3 = alice.createNewInvoice(alice_pk, Amount(2_000), time_t.max, "payment 3");
    bob.payInvoice(bob_pk, inv_3.value);

    alice.waitForUpdateIndex(alice_pk, chan_id, 6);
    bob.waitForUpdateIndex(bob_pk, chan_id, 6);

    log.info("Alice collaboratively closing the channel..");
    auto error = alice.beginCollaborativeClose(alice_pk, chan_id).error;
    assert(error == ErrorCode.None, error.to!string);
    // note: not checking for StartedUnilateralClose due to timing
    factory.listener.waitUntilChannelState(chan_id,
        ChannelState.RejectedCollaborativeClose);

    log.info("Alice unilaterally closing the channel..");
    error = alice.beginUnilateralClose(alice_pk, chan_id).error;
    assert(error == ErrorCode.None, error.to!string);
    factory.listener.waitUntilChannelState(chan_id,
        ChannelState.StartedUnilateralClose);

    // trigger tx published
    network.expectHeightAndPreImg(Height(10), network.blocks[0].header);

    // latest update tx published
    network.expectHeightAndPreImg(Height(11), network.blocks[0].header);

    // latest settle tx published
    network.expectHeightAndPreImg(Height(12), network.blocks[0].header);
    factory.listener.waitUntilChannelState(chan_id, ChannelState.Closed);
}

/// Test indirect channel payments
//version (none)
unittest
{
    TestConf conf = { payout_period : 100 };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];
    scope (failure) node_1.printLog();

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();

    foreach (idx, tx; txs)
    {
        node_1.putTransaction(tx);
        network.expectHeightAndPreImg(Height(idx + 1), network.blocks[0].header);
    }

    auto factory = new FlashNodeFactory!()(network.getRegistry());
    scope (exit) factory.shutdown();
    scope (failure) factory.printLogs();

    const alice_pair = Pair(WK.Keys[0].secret, WK.Keys[0].secret.toPoint);
    const bob_pair = Pair(WK.Keys[1].secret, WK.Keys[1].secret.toPoint);
    const charlie_pair = Pair(WK.Keys[2].secret, WK.Keys[2].secret.toPoint);

    const alice_pk = alice_pair.V;
    const bob_pk = bob_pair.V;
    const charlie_pk = charlie_pair.V;

    const alice_pubkey = PublicKey(alice_pair.V);
    const bob_pubkey = PublicKey(bob_pair.V);
    const charlie_pubkey = PublicKey(charlie_pair.V);

    // workaround to get a handle to the node from another registry's thread
    const string address = format("Validator #%s (%s)", 0, genesis_validator_keys[0].address);
    auto alice = factory.create(alice_pair, address);
    auto bob = factory.create(bob_pair, address);
    auto charlie = factory.create(charlie_pair, address);

    // 0 blocks settle time after trigger tx is published (unsafe)
    const Settle_1_Blocks = 0;
    //const Settle_10_Blocks = 10;

    /+ OPEN ALICE => BOB CHANNEL +/
    /+++++++++++++++++++++++++++++++++++++++++++++/
    // the utxo the funding tx will spend (only relevant to the funder)
    const alice_utxo = UTXO(0, txs[0].outputs[0]);
    const alice_utxo_hash = UTXO.getHash(hashFull(txs[0]), 0);
    const alice_bob_chan_id_res = alice.openNewChannel(alice_pubkey,
        alice_utxo, alice_utxo_hash, Amount(10_000), Settle_1_Blocks, bob_pk);
    assert(alice_bob_chan_id_res.error == ErrorCode.None,
        alice_bob_chan_id_res.message);
    const alice_bob_chan_id = alice_bob_chan_id_res.value;
    log.info("Alice bob channel ID: {}", alice_bob_chan_id);
    factory.listener.waitUntilChannelState(alice_bob_chan_id,
        ChannelState.SettingUp);

    // await alice & bob channel funding transaction
    network.expectHeightAndPreImg(Height(9), network.blocks[0].header);
    const block_9 = node_1.getBlocksFrom(9, 1)[$ - 1];
    assert(block_9.txs.any!(tx => tx.hashFull() == alice_bob_chan_id));

    // wait for the parties to detect the funding tx
    alice.waitForChannelOpen(alice_pubkey, alice_bob_chan_id);
    bob.waitForChannelOpen(bob_pubkey, alice_bob_chan_id);
    factory.listener.waitUntilChannelState(alice_bob_chan_id, ChannelState.Open);

    /+++++++++++++++++++++++++++++++++++++++++++++/

    /+ OPEN BOB => CHARLIE CHANNEL +/
    /+++++++++++++++++++++++++++++++++++++++++++++/
    // the utxo the funding tx will spend (only relevant to the funder)
    const bob_utxo = UTXO(0, txs[1].outputs[0]);
    const bob_utxo_hash = UTXO.getHash(hashFull(txs[1]), 0);
    const bob_charlie_chan_id_res = bob.openNewChannel(bob_pubkey,
        bob_utxo, bob_utxo_hash, Amount(3_000), Settle_1_Blocks, charlie_pk);
    assert(bob_charlie_chan_id_res.error == ErrorCode.None,
        bob_charlie_chan_id_res.message);
    const bob_charlie_chan_id = bob_charlie_chan_id_res.value;
    log.info("Bob Charlie channel ID: {}", bob_charlie_chan_id);
    factory.listener.waitUntilChannelState(bob_charlie_chan_id,
        ChannelState.SettingUp);

    // await bob & bob channel funding transaction
    network.expectHeightAndPreImg(Height(10), network.blocks[0].header);
    const block_10 = node_1.getBlocksFrom(10, 1)[$ - 1];
    assert(block_10.txs.any!(tx => tx.hashFull() == bob_charlie_chan_id));

    // wait for the parties to detect the funding tx
    bob.waitForChannelOpen(bob_pubkey, bob_charlie_chan_id);
    charlie.waitForChannelOpen(charlie_pubkey, bob_charlie_chan_id);
    factory.listener.waitUntilChannelState(bob_charlie_chan_id, ChannelState.Open);
    /+++++++++++++++++++++++++++++++++++++++++++++/

    // also wait for all parties to discover other channels on the network
    alice.waitForChannelDiscovery(bob_charlie_chan_id);
    charlie.waitForChannelDiscovery(alice_bob_chan_id);

    // begin off-chain transactions
    auto inv_1 = charlie.createNewInvoice(charlie_pubkey, Amount(2_000),
        time_t.max, "payment 1");

    // here we assume bob sent the invoice to alice through some means,
    // e.g. QR code. Alice scans it and proposes the payment.
    // it has a direct channel to bob so it uses it.
    alice.payInvoice(alice_pubkey, inv_1.value);
    auto inv_res = factory.listener.waitUntilNotified(inv_1.value);
    assert(inv_res == ErrorCode.None, format("Couldn't pay invoice: %s", inv_res));

    // wait for payment + folding update indices
    alice.waitForUpdateIndex(alice_pubkey, alice_bob_chan_id, 2);
    bob.waitForUpdateIndex(bob_pubkey, alice_bob_chan_id, 2);
    bob.waitForUpdateIndex(bob_pubkey, bob_charlie_chan_id, 2);
    charlie.waitForUpdateIndex(charlie_pubkey, bob_charlie_chan_id, 2);

    //
    log.info("Beginning bob => charlie collaborative close..");
    assert(bob.beginCollaborativeClose(bob_pubkey, bob_charlie_chan_id).error
        == ErrorCode.None);
    network.expectHeightAndPreImg(Height(11), network.blocks[0].header);
    auto block11 = node_1.getBlocksFrom(11, 1)[0];
    log.info("bob closing tx: {}", bob.getClosingTx(bob_pubkey,
        bob_charlie_chan_id));
    assert(block11.txs.canFind(bob.getClosingTx(bob_pubkey, bob_charlie_chan_id)));
    factory.listener.waitUntilChannelState(bob_charlie_chan_id,
        ChannelState.Closed);

    // can't close twice
    assert(bob.beginCollaborativeClose(bob_pubkey, bob_charlie_chan_id).error
        == ErrorCode.ChannelNotOpen);

    log.info("Beginning alice => bob collaborative close..");
    assert(alice.beginCollaborativeClose(alice_pubkey,
        alice_bob_chan_id).error == ErrorCode.None);
    network.expectHeightAndPreImg(Height(12), network.blocks[0].header);
    auto block12 = node_1.getBlocksFrom(12, 1)[0];
    log.info("alice closing tx: {}", alice.getClosingTx(alice_pubkey,
        alice_bob_chan_id));
    assert(block12.txs.canFind(alice.getClosingTx(alice_pubkey, alice_bob_chan_id)));
    factory.listener.waitUntilChannelState(alice_bob_chan_id,
        ChannelState.Closed);
}

/// Test path probing
unittest
{
    TestConf conf = { payout_period : 100 };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];
    scope (failure) node_1.printLog();

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();

    foreach (idx, tx; txs)
    {
        node_1.putTransaction(tx);
        network.expectHeightAndPreImg(Height(idx + 1), network.blocks[0].header);
    }

    auto factory = new FlashNodeFactory!()(network.getRegistry());
    scope (exit) factory.shutdown();
    scope (failure) factory.printLogs();

    const alice_pair = Pair(WK.Keys[0].secret, WK.Keys[0].secret.toPoint);
    const bob_pair = Pair(WK.Keys[1].secret, WK.Keys[1].secret.toPoint);
    const charlie_pair = Pair(WK.Keys[2].secret, WK.Keys[2].secret.toPoint);

    const alice_pk = alice_pair.V;
    const bob_pk = bob_pair.V;
    const charlie_pk = charlie_pair.V;

    const alice_pubkey = PublicKey(alice_pair.V);
    const bob_pubkey = PublicKey(bob_pair.V);
    const charlie_pubkey = PublicKey(charlie_pair.V);

    // workaround to get a handle to the node from another registry's thread
    const string address = format("Validator #%s (%s)", 0, genesis_validator_keys[0].address);

    FlashConfig alice_conf = { enabled : true,
        min_funding : Amount(1000),
        max_funding : Amount(100_000_000),
        min_settle_time : 0,
        max_settle_time : 100,
        listener_address : factory.ListenerAddress,
        max_retry_time : 4.seconds,
        max_retry_delay : 100.msecs,
    };

    auto alice = factory.create(alice_pair, alice_conf, address);
    auto bob = factory.create(bob_pair, address);
    auto charlie = factory.create(charlie_pair, address);

    // 0 blocks settle time after trigger tx is published (unsafe)
    const Settle_1_Blocks = 0;
    //const Settle_10_Blocks = 10;

    /+ OPEN ALICE => BOB CHANNEL +/
    /+++++++++++++++++++++++++++++++++++++++++++++/
    // the utxo the funding tx will spend (only relevant to the funder)
    const alice_utxo = UTXO(0, txs[0].outputs[0]);
    const alice_utxo_hash = UTXO.getHash(hashFull(txs[0]), 0);
    const alice_bob_chan_id_res = alice.openNewChannel(alice_pubkey,
        alice_utxo, alice_utxo_hash, Amount(10_000), Settle_1_Blocks, bob_pk);
    assert(alice_bob_chan_id_res.error == ErrorCode.None,
        alice_bob_chan_id_res.message);
    const alice_bob_chan_id = alice_bob_chan_id_res.value;
    log.info("Alice bob channel ID: {}", alice_bob_chan_id);
    factory.listener.waitUntilChannelState(alice_bob_chan_id,
        ChannelState.SettingUp);

    // await alice & bob channel funding transaction
    network.expectHeightAndPreImg(Height(9), network.blocks[0].header);
    const block_9 = node_1.getBlocksFrom(9, 1)[$ - 1];
    assert(block_9.txs.any!(tx => tx.hashFull() == alice_bob_chan_id));

    // wait for the parties to detect the funding tx
    alice.waitForChannelOpen(alice_pubkey, alice_bob_chan_id);
    bob.waitForChannelOpen(bob_pubkey, alice_bob_chan_id);
    factory.listener.waitUntilChannelState(alice_bob_chan_id, ChannelState.Open);
    /+++++++++++++++++++++++++++++++++++++++++++++/

    /+ OPEN BOB => CHARLIE CHANNEL +/
    /+++++++++++++++++++++++++++++++++++++++++++++/
    // the utxo the funding tx will spend (only relevant to the funder)
    const bob_utxo = UTXO(0, txs[1].outputs[0]);
    const bob_utxo_hash = UTXO.getHash(hashFull(txs[1]), 0);
    const bob_charlie_chan_id_res = bob.openNewChannel(bob_pubkey,
        bob_utxo, bob_utxo_hash, Amount(10_000), Settle_1_Blocks, charlie_pk);
    assert(bob_charlie_chan_id_res.error == ErrorCode.None,
        bob_charlie_chan_id_res.message);
    const bob_charlie_chan_id = bob_charlie_chan_id_res.value;
    log.info("Bob Charlie channel ID: {}", bob_charlie_chan_id);
    factory.listener.waitUntilChannelState(bob_charlie_chan_id,
        ChannelState.SettingUp);

    // await bob & bob channel funding transaction
    network.expectHeightAndPreImg(Height(10), network.blocks[0].header);
    const block_10 = node_1.getBlocksFrom(10, 1)[$ - 1];
    assert(block_10.txs.any!(tx => tx.hashFull() == bob_charlie_chan_id));

    // wait for the parties to detect the funding tx
    bob.waitForChannelOpen(bob_pubkey, bob_charlie_chan_id);
    charlie.waitForChannelOpen(charlie_pubkey, bob_charlie_chan_id);
    factory.listener.waitUntilChannelState(bob_charlie_chan_id, ChannelState.Open);
    /+++++++++++++++++++++++++++++++++++++++++++++/

    /+ OPEN CHARLIE => ALICE CHANNEL +/
    /+++++++++++++++++++++++++++++++++++++++++++++/
    // the utxo the funding tx will spend (only relevant to the funder)
    const charlie_utxo = UTXO(0, txs[2].outputs[0]);
    const charlie_utxo_hash = UTXO.getHash(hashFull(txs[2]), 0);
    const charlie_alice_chan_id_res = charlie.openNewChannel(charlie_pubkey,
        charlie_utxo, charlie_utxo_hash, Amount(10_000), Settle_1_Blocks, alice_pk);
    assert(charlie_alice_chan_id_res.error == ErrorCode.None,
        charlie_alice_chan_id_res.message);
    const charlie_alice_chan_id = charlie_alice_chan_id_res.value;
    log.info("Charlie Alice channel ID: {}", charlie_alice_chan_id);
    factory.listener.waitUntilChannelState(charlie_alice_chan_id,
        ChannelState.SettingUp);

    // await bob & bob channel funding transaction
    network.expectHeightAndPreImg(Height(11), network.blocks[0].header);
    const block_11 = node_1.getBlocksFrom(11, 1)[$ - 1];
    assert(block_11.txs.any!(tx => tx.hashFull() == charlie_alice_chan_id));

    // wait for the parties to detect the funding tx
    alice.waitForChannelOpen(alice_pubkey, charlie_alice_chan_id);
    charlie.waitForChannelOpen(charlie_pubkey, charlie_alice_chan_id);
    factory.listener.waitUntilChannelState(charlie_alice_chan_id, ChannelState.Open);
    /+++++++++++++++++++++++++++++++++++++++++++++/

    // also wait for all parties to discover other channels on the network
    alice.waitForChannelDiscovery(bob_charlie_chan_id);
    bob.waitForChannelDiscovery(charlie_alice_chan_id);
    charlie.waitForChannelDiscovery(alice_bob_chan_id);

    // begin off-chain transactions
    auto inv_1 = charlie.createNewInvoice(charlie_pubkey, Amount(2_000),
        time_t.max, "payment 1");

    // here we assume bob sent the invoice to alice through some means,

    // Alice has a direct channel to charlie, but it does not have enough funds
    // to complete the payment in that direction. Alice will first naively try
    // that route and fail. In the second try, alice will route the payment through bob.
    alice.payInvoice(alice_pubkey, inv_1.value);
    auto res1 = factory.listener.waitUntilNotified(inv_1.value);
    assert(res1 != ErrorCode.None);  // should fail at first
    alice.payInvoice(alice_pubkey, inv_1.value);
    auto res2 = factory.listener.waitUntilNotified(inv_1.value);
    assert(res2 == ErrorCode.None);  // should succeed the second time

    bob.waitForUpdateIndex(bob_pubkey, bob_charlie_chan_id, 2);
    charlie.waitForUpdateIndex(charlie_pubkey, bob_charlie_chan_id, 2);

    alice.changeFees(alice_pubkey, charlie_alice_chan_id, Amount(1337),
        Amount(1));
    auto update = alice.waitForChannelUpdate(charlie_alice_chan_id,
        PaymentDirection.TowardsOwner, 1);
    assert(update.fixed_fee == Amount(1337));
    assert(update.proportional_fee == Amount(1));
    update = bob.waitForChannelUpdate(charlie_alice_chan_id,
        PaymentDirection.TowardsOwner, 1);
    assert(update.fixed_fee == Amount(1337));
    assert(update.proportional_fee == Amount(1));
    update = charlie.waitForChannelUpdate(charlie_alice_chan_id,
        PaymentDirection.TowardsOwner, 1);
    assert(update.fixed_fee == Amount(1337));
    assert(update.proportional_fee == Amount(1));
}

/// Test path probing
unittest
{
    TestConf conf = { payout_period : 100 };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];
    scope (failure) node_1.printLog();

    // split the genesis funds into WK.Keys[0] .. WK.Keys[3]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index / 2].address).sign())
        .array();

    foreach (idx, tx; txs)
    {
        node_1.putTransaction(tx);
        network.expectHeightAndPreImg(Height(idx + 1), network.blocks[0].header);
    }

    auto factory = new FlashNodeFactory!()(network.getRegistry());
    scope (exit) factory.shutdown();
    scope (failure) factory.printLogs();

    const alice_pair = Pair(WK.Keys[0].secret, WK.Keys[0].secret.toPoint);
    const bob_pair = Pair(WK.Keys[1].secret, WK.Keys[1].secret.toPoint);
    const charlie_pair = Pair(WK.Keys[2].secret, WK.Keys[2].secret.toPoint);

    const alice_pk = alice_pair.V;
    const bob_pk = bob_pair.V;
    const charlie_pk = charlie_pair.V;

    const alice_pubkey = PublicKey(alice_pair.V);
    const bob_pubkey = PublicKey(bob_pair.V);
    const charlie_pubkey = PublicKey(charlie_pair.V);

    // workaround to get a handle to the node from another registry's thread
    const string address = format("Validator #%s (%s)", 0, genesis_validator_keys[0].address);
    auto alice = factory.create(alice_pair, address);
    auto bob = factory.create(bob_pair, address);
    auto charlie = factory.create(charlie_pair, address);

    // 0 blocks settle time after trigger tx is published (unsafe)
    const Settle_1_Blocks = 0;
    //const Settle_10_Blocks = 10;

    /+ OPEN ALICE => BOB CHANNEL +/
    /+++++++++++++++++++++++++++++++++++++++++++++/
    // the utxo the funding tx will spend (only relevant to the funder)
    const alice_utxo = UTXO(0, txs[0].outputs[0]);
    const alice_utxo_hash = UTXO.getHash(hashFull(txs[0]), 0);
    const alice_bob_chan_id_res = alice.openNewChannel(alice_pubkey,
        alice_utxo, alice_utxo_hash, Amount(10_000), Settle_1_Blocks, bob_pk);
    assert(alice_bob_chan_id_res.error == ErrorCode.None,
        alice_bob_chan_id_res.message);
    const alice_bob_chan_id = alice_bob_chan_id_res.value;
    log.info("Alice bob channel ID: {}", alice_bob_chan_id);
    factory.listener.waitUntilChannelState(alice_bob_chan_id,
        ChannelState.SettingUp);

    // await alice & bob channel funding transaction
    network.expectHeightAndPreImg(Height(9), network.blocks[0].header);
    const block_9 = node_1.getBlocksFrom(9, 1)[$ - 1];
    assert(block_9.txs.any!(tx => tx.hashFull() == alice_bob_chan_id));

    // wait for the parties to detect the funding tx
    alice.waitForChannelOpen(alice_pubkey, alice_bob_chan_id);
    bob.waitForChannelOpen(bob_pubkey, alice_bob_chan_id);
    factory.listener.waitUntilChannelState(alice_bob_chan_id, ChannelState.Open);
    /+++++++++++++++++++++++++++++++++++++++++++++/

    /+ OPEN BOB => CHARLIE CHANNEL +/
    /+++++++++++++++++++++++++++++++++++++++++++++/
    // the utxo the funding tx will spend (only relevant to the funder)
    const bob_utxo = UTXO(0, txs[2].outputs[0]);
    const bob_utxo_hash = UTXO.getHash(hashFull(txs[2]), 0);
    const bob_charlie_chan_id_res = bob.openNewChannel(bob_pubkey,
        bob_utxo, bob_utxo_hash, Amount(10_000), Settle_1_Blocks, charlie_pk);
    assert(bob_charlie_chan_id_res.error == ErrorCode.None,
        bob_charlie_chan_id_res.message);
    const bob_charlie_chan_id = bob_charlie_chan_id_res.value;
    log.info("Bob Charlie channel ID: {}", bob_charlie_chan_id);
    factory.listener.waitUntilChannelState(bob_charlie_chan_id,
        ChannelState.SettingUp);

    // await bob & bob channel funding transaction
    network.expectHeightAndPreImg(Height(10), network.blocks[0].header);
    const block_10 = node_1.getBlocksFrom(10, 1)[$ - 1];
    assert(block_10.txs.any!(tx => tx.hashFull() == bob_charlie_chan_id));

    // wait for the parties to detect the funding tx
    bob.waitForChannelOpen(bob_pubkey, bob_charlie_chan_id);
    charlie.waitForChannelOpen(charlie_pubkey, bob_charlie_chan_id);
    factory.listener.waitUntilChannelState(bob_charlie_chan_id, ChannelState.Open);
    alice.waitForChannelDiscovery(bob_charlie_chan_id);  // also alice (so it can detect fees)

    bob.changeFees(bob_pubkey, bob_charlie_chan_id, Amount(100), Amount(1));
    alice.waitForChannelUpdate(bob_charlie_chan_id, PaymentDirection.TowardsPeer, 1);
    charlie.waitForChannelUpdate(bob_charlie_chan_id, PaymentDirection.TowardsPeer, 1);
    /+++++++++++++++++++++++++++++++++++++++++++++/

    /+ OPEN SECOND BOB => CHARLIE CHANNEL +/
    /+++++++++++++++++++++++++++++++++++++++++++++/
    // the utxo the funding tx will spend (only relevant to the funder)
    const bob_utxo_2 = UTXO(0, txs[3].outputs[0]);
    const bob_utxo_hash_2 = UTXO.getHash(hashFull(txs[3]), 0);
    const bob_charlie_chan_id_2_res = bob.openNewChannel(bob_pubkey,
        bob_utxo_2, bob_utxo_hash_2, Amount(10_000), Settle_1_Blocks, charlie_pk);
    assert(bob_charlie_chan_id_2_res.error == ErrorCode.None,
        bob_charlie_chan_id_2_res.message);
    const bob_charlie_chan_id_2 = bob_charlie_chan_id_2_res.value;
    log.info("Bob Charlie channel ID: {}", bob_charlie_chan_id_2);
    factory.listener.waitUntilChannelState(bob_charlie_chan_id_2,
        ChannelState.SettingUp, bob_pubkey);

    auto chans = bob.getManagedChannels(null);
    assert(chans.length == 3, chans.to!string);

    chans = bob.getManagedChannels([bob_pubkey]);
    assert(chans.length == 3, chans.to!string);

    chans = bob.getManagedChannels([alice_pubkey]);
    assert(chans.length == 0, chans.to!string);

    auto infos = bob.getChannelInfo([bob_charlie_chan_id_2]);
    assert(infos.length == 1);
    auto info = infos[0];
    assert(info.chan_id == bob_charlie_chan_id_2);
    assert(info.owner_key == bob_pubkey);
    assert(info.peer_key == charlie_pubkey);
    assert(info.state == ChannelState.Negotiating
        || info.state == ChannelState.SettingUp
        || info.state == ChannelState.WaitingForFunding, info.state.to!string);
    assert(info.owner_balance == Amount(0), info.owner_balance.to!string);
    assert(info.peer_balance == Amount(0), info.peer_balance.to!string);

    // await bob & bob channel funding transaction
    network.expectHeightAndPreImg(Height(11), network.blocks[0].header);
    const block_11 = node_1.getBlocksFrom(11, 1)[$ - 1];
    assert(block_11.txs.any!(tx => tx.hashFull() == bob_charlie_chan_id_2));

    // wait for the parties to detect the funding tx
    bob.waitForChannelOpen(bob_pubkey, bob_charlie_chan_id_2);
    charlie.waitForChannelOpen(charlie_pubkey, bob_charlie_chan_id_2);
    factory.listener.waitUntilChannelState(bob_charlie_chan_id_2, ChannelState.Open);

    // check if info is different now
    infos = bob.getChannelInfo([bob_charlie_chan_id_2]);
    assert(infos.length == 1);
    info = infos[0];
    assert(info.state == ChannelState.Open);
    assert(info.owner_balance == Amount(10_000), info.owner_balance.to!string);
    assert(info.peer_balance == Amount(0), info.peer_balance.to!string);

    bob.changeFees(bob_pubkey, bob_charlie_chan_id_2, Amount(10), Amount(1));
    alice.waitForChannelUpdate(bob_charlie_chan_id_2, PaymentDirection.TowardsPeer, 1);
    charlie.waitForChannelUpdate(bob_charlie_chan_id_2, PaymentDirection.TowardsPeer, 1);
    /+++++++++++++++++++++++++++++++++++++++++++++/

    // also wait for all parties to discover other channels on the network
    alice.waitForChannelDiscovery(bob_charlie_chan_id);
    alice.waitForChannelDiscovery(bob_charlie_chan_id_2);
    charlie.waitForChannelDiscovery(alice_bob_chan_id);

    // begin off-chain transactions
    auto inv_1 = charlie.createNewInvoice(charlie_pubkey, Amount(2_000),
        time_t.max, "payment 1");

    // Alice is expected to route the payment through the channel
    // with lower fee between Bob and Charlie
    alice.payInvoice(alice_pubkey, inv_1.value);

    // wait for payment + folding update indices
    alice.waitForUpdateIndex(alice_pubkey, alice_bob_chan_id, 2);
    bob.waitForUpdateIndex(bob_pubkey, alice_bob_chan_id, 2);
    bob.waitForUpdateIndex(bob_pubkey, bob_charlie_chan_id_2, 2);
    charlie.waitForUpdateIndex(charlie_pubkey, bob_charlie_chan_id_2, 2);

    assert(bob.beginCollaborativeClose(bob_pubkey, bob_charlie_chan_id_2).error
        == ErrorCode.None);
    network.expectHeightAndPreImg(Height(12), network.blocks[0].header);
    factory.listener.waitUntilChannelState(bob_charlie_chan_id_2,
        ChannelState.Closed);
    auto block12 = node_1.getBlocksFrom(12, 1)[0];
    auto closing_tx = bob.getClosingTx(bob_pubkey, bob_charlie_chan_id_2);
    assert(block12.txs.canFind(closing_tx));
    assert(closing_tx.outputs.length == 2);
    assert(closing_tx.outputs.count!(o => o.value == Amount(8000)) == 1); // No fees
    assert(closing_tx.outputs.count!(o => o.value == Amount(2000 - closing_tx.sizeInBytes)) == 1); // Minus the closing TX fee

    assert(alice.beginCollaborativeClose(alice_pubkey, alice_bob_chan_id).error
        == ErrorCode.None);
    network.expectHeightAndPreImg(Height(13), network.blocks[0].header);
    factory.listener.waitUntilChannelState(alice_bob_chan_id,
        ChannelState.Closed);
    auto block13 = node_1.getBlocksFrom(13, 1)[0];
    closing_tx = alice.getClosingTx(alice_pubkey, alice_bob_chan_id);
    assert(block13.txs.canFind(closing_tx));
    assert(closing_tx.outputs.length == 2);
    assert(closing_tx.outputs.count!(o => o.value == Amount(7990)) == 1); // Fees
    assert(closing_tx.outputs.count!(o => o.value == Amount(2010 - closing_tx.sizeInBytes)) == 1); // Minus the closing TX fee

    assert(bob.beginCollaborativeClose(bob_pubkey, bob_charlie_chan_id).error
        == ErrorCode.None);
    network.expectHeightAndPreImg(Height(14), network.blocks[0].header);
    factory.listener.waitUntilChannelState(bob_charlie_chan_id,
        ChannelState.Closed);
    auto block14 = node_1.getBlocksFrom(14, 1)[0];
    closing_tx = bob.getClosingTx(bob_pubkey, bob_charlie_chan_id);
    assert(block14.txs.canFind(closing_tx));
    assert(closing_tx.outputs.length == 1); // No updates
}

unittest
{
    static class BleedingEdgeFlashNode : TestFlashNode
    {
        mixin ForwardCtor!();

        ///
        protected override void paymentRouter (in PublicKey pk, in Hash chan_id,
            in Hash payment_hash, in Amount amount,
            in Height lock_height, in OnionPacket packet)
        {
            OnionPacket hijacked = packet;
            hijacked.version_byte += 1;
            super.paymentRouter(pk, chan_id, payment_hash, amount,
                lock_height, hijacked);
        }
    }

    TestConf conf = { payout_period : 100 };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope (exit) network.shutdown();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();

    foreach (idx, tx; txs)
    {
        node_1.putTransaction(tx);
        network.expectHeightAndPreImg(Height(idx + 1), network.blocks[0].header);
    }

    auto factory = new FlashNodeFactory!()(network.getRegistry());
    scope (exit) factory.shutdown();
    scope (failure) factory.printLogs();

    const alice_pair = Pair(WK.Keys[0].secret, WK.Keys[0].secret.toPoint);
    const bob_pair = Pair(WK.Keys[1].secret, WK.Keys[1].secret.toPoint);

    const bob_pk = bob_pair.V;

    const alice_pubkey = PublicKey(alice_pair.V);
    const bob_pubkey = PublicKey(bob_pair.V);

    // workaround to get a handle to the node from another registry's thread
    const string address = format("Validator #%s (%s)", 0, genesis_validator_keys[0].address);
    auto alice = factory.create!BleedingEdgeFlashNode(alice_pair, address);
    auto bob = factory.create(bob_pair, address);

    /+ OPEN ALICE => BOB CHANNEL +/
    /+++++++++++++++++++++++++++++++++++++++++++++/
    // the utxo the funding tx will spend (only relevant to the funder)
    const alice_utxo = UTXO(0, txs[0].outputs[0]);
    const alice_utxo_hash = UTXO.getHash(hashFull(txs[0]), 0);
    const alice_bob_chan_id_res = alice.openNewChannel(alice_pubkey,
        alice_utxo, alice_utxo_hash, Amount(10_000), 0, bob_pk);
    assert(alice_bob_chan_id_res.error == ErrorCode.None,
        alice_bob_chan_id_res.message);
    const alice_bob_chan_id = alice_bob_chan_id_res.value;
    log.info("Alice bob channel ID: {}", alice_bob_chan_id);
    factory.listener.waitUntilChannelState(alice_bob_chan_id,
        ChannelState.SettingUp);

    // await alice & bob channel funding transaction
    network.expectHeightAndPreImg(Height(9), network.blocks[0].header);
    const block_9 = node_1.getBlocksFrom(9, 1)[$ - 1];
    assert(block_9.txs.any!(tx => tx.hashFull() == alice_bob_chan_id));

    // wait for the parties to detect the funding tx
    alice.waitForChannelOpen(alice_pubkey, alice_bob_chan_id);
    bob.waitForChannelOpen(bob_pubkey, alice_bob_chan_id);
    factory.listener.waitUntilChannelState(alice_bob_chan_id, ChannelState.Open);
    /+++++++++++++++++++++++++++++++++++++++++++++/

    // begin off-chain transactions
    auto inv_1 = bob.createNewInvoice(bob_pubkey, Amount(2_000), time_t.max, "payment 1");

    // Bob will receive packets with a different version than it implements
    alice.payInvoice(alice_pubkey, inv_1.value);
    Thread.sleep(1.seconds);

    assert(bob.beginCollaborativeClose(bob_pubkey, alice_bob_chan_id).error
        == ErrorCode.None);
    network.expectHeightAndPreImg(Height(10), network.blocks[0].header);
    factory.listener.waitUntilChannelState(alice_bob_chan_id,
        ChannelState.Closed);
    auto block10 = node_1.getBlocksFrom(10, 1)[0];
    auto closing_tx = bob.getClosingTx(bob_pubkey, alice_bob_chan_id);
    assert(block10.txs.canFind(closing_tx));
    assert(closing_tx.outputs.length == 1); // No updates
}

/// Test node serialization & loading
//version (none)
unittest
{
    TestConf conf = { payout_period : 100 };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];
    scope (failure) node_1.printLog();

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();

    foreach (idx, tx; txs)
    {
        node_1.putTransaction(tx);
        network.expectHeightAndPreImg(Height(idx + 1), network.blocks[0].header);
    }

    auto factory = new FlashNodeFactory!()(network.getRegistry());
    scope (exit) factory.shutdown();
    scope (failure) factory.printLogs();

    const alice_pair = Pair(WK.Keys[0].secret, WK.Keys[0].secret.toPoint);
    const bob_pair = Pair(WK.Keys[1].secret, WK.Keys[1].secret.toPoint);

    const alice_pubkey = PublicKey(alice_pair.V);
    const bob_pubkey = PublicKey(bob_pair.V);

    // workaround to get a handle to the node from another registry's thread
    const string address = format("Validator #%s (%s)", 0, genesis_validator_keys[0].address);
    auto alice = factory.create(alice_pair, address, DatabaseStorage.Static);
    auto bob = factory.create(bob_pair, address, DatabaseStorage.Static);

    // 0 blocks settle time after trigger tx is published (unsafe)
    const Settle_1_Blocks = 0;

    // the utxo the funding tx will spend (only relevant to the funder)
    const utxo = UTXO(0, txs[0].outputs[0]);
    const utxo_hash = UTXO.getHash(hashFull(txs[0]), 0);
    const chan_id_res = alice.openNewChannel(alice_pubkey,
        utxo, utxo_hash, Amount(10_000), Settle_1_Blocks, bob_pair.V);
    assert(chan_id_res.error == ErrorCode.None,
        chan_id_res.message);
    const chan_id = chan_id_res.value;
    factory.listener.waitUntilChannelState(chan_id, ChannelState.SettingUp);

    // await funding transaction
    network.expectHeightAndPreImg(Height(9), network.blocks[0].header);
    const block_9 = node_1.getBlocksFrom(9, 1)[$ - 1];
    assert(block_9.txs.any!(tx => tx.hashFull() == chan_id));

    // wait for the parties to detect the funding tx
    alice.waitForChannelOpen(alice_pubkey, chan_id);
    bob.waitForChannelOpen(bob_pubkey, chan_id);
    factory.listener.waitUntilChannelState(chan_id, ChannelState.Open);

    auto update_tx = alice.getPublishUpdateIndex(alice_pubkey, chan_id, 0);

    /* do some off-chain transactions */
    auto inv_1 = bob.createNewInvoice(bob_pubkey, Amount(5_000), time_t.max, "payment 1");
    alice.payInvoice(alice_pubkey, inv_1.value);

    alice.waitForUpdateIndex(alice_pubkey, chan_id, 2);
    bob.waitForUpdateIndex(bob_pubkey, chan_id, 2);

    auto inv_2 = bob.createNewInvoice(bob_pubkey, Amount(1_000), time_t.max, "payment 2");
    alice.payInvoice(alice_pubkey, inv_2.value);

    // need to wait for invoices to be complete before we have the new balance
    // to send in the other direction
    alice.waitForUpdateIndex(alice_pubkey, chan_id, 4);
    bob.waitForUpdateIndex(bob_pubkey, chan_id, 4);

    // restart the two nodes
    factory.restart();

    // note the reverse payment from bob to alice. Can use this for refunds too.
    auto inv_3 = alice.createNewInvoice(alice_pubkey, Amount(2_000), time_t.max, "payment 3");
    bob.payInvoice(bob_pubkey, inv_3.value);

    // next update index should be 6
    alice.waitForUpdateIndex(alice_pubkey, chan_id, 6);
    bob.waitForUpdateIndex(bob_pubkey, chan_id, 6);
}

/// test various error cases
unittest
{
    TestConf conf = { payout_period : 100 };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];
    scope (failure) node_1.printLog();

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();

    foreach (idx, tx; txs)
    {
        node_1.putTransaction(tx);
        network.expectHeightAndPreImg(Height(idx + 1), network.blocks[0].header);
    }

    auto factory = new FlashNodeFactory!()(network.getRegistry());
    scope (exit) factory.shutdown();
    scope (failure) factory.printLogs();

    const alice_pair = Pair(WK.Keys[0].secret, WK.Keys[0].secret.toPoint);
    const bob_pair = Pair(WK.Keys[1].secret, WK.Keys[1].secret.toPoint);

    // workaround to get a handle to the node from another registry's thread
    const string address = format("Validator #%s (%s)", 0, genesis_validator_keys[0].address);

    FlashConfig bob_conf = { enabled : true,
        min_funding : Amount(1000),
        max_funding : Amount(100_000_000),
        min_settle_time : 10,
        max_settle_time : 100,
        max_retry_delay : 100.msecs,
    };
    auto alice = factory.create(alice_pair, address);
    auto bob = factory.create(bob_pair, bob_conf, address);

    const alice_pubkey = PublicKey(alice_pair.V);
    const bob_pubkey = PublicKey(bob_pair.V);

    const Settle_10_Blocks = 10;

    // the utxo the funding tx will spend (only relevant to the funder)
    const utxo = UTXO(0, txs[0].outputs[0]);
    const utxo_hash = UTXO.getHash(hashFull(txs[0]), 0);

    // error on mismatching genesis hash
    ChannelConfig bad_conf = { funder_pk : alice_pair.V };
    auto open_res = bob.openChannel(bob_pubkey, bad_conf, PublicNonce.init);
    assert(open_res.error == ErrorCode.InvalidGenesisHash, open_res.to!string);

    // error on non-managed key
    open_res = bob.openChannel(alice_pubkey, bad_conf, PublicNonce.init);
    assert(open_res.error == ErrorCode.KeyNotRecognized, open_res.to!string);

    // error on capacity too low
    auto res = alice.openNewChannel(alice_pubkey,
        utxo, utxo_hash, Amount(1), Settle_10_Blocks, bob_pair.V);
    assert(res.error == ErrorCode.None);

    auto error = factory.listener.waitUntilChannelState(res.value,
        ChannelState.Rejected);
    assert(error == ErrorCode.RejectedFundingAmount, res.to!string);

    // channel does not exist as it was rejected
    assert(alice.beginCollaborativeClose(alice_pubkey, res.value).error
        == ErrorCode.InvalidChannelID);

    // error on capacity too high
    res = alice.openNewChannel(alice_pubkey,
        utxo, utxo_hash, Amount(1_000_000_000), Settle_10_Blocks, bob_pair.V);
    assert(res.error == ErrorCode.None);

    error = factory.listener.waitUntilChannelState(res.value,
        ChannelState.Rejected);
    assert(error == ErrorCode.RejectedFundingAmount, res.to!string);

    // error on settle time too low
    res = alice.openNewChannel(alice_pubkey,
        utxo, utxo_hash, Amount(10_000), 5, bob_pair.V);
    assert(res.error == ErrorCode.None);

    error = factory.listener.waitUntilChannelState(res.value,
        ChannelState.Rejected);
    assert(error == ErrorCode.RejectedSettleTime, res.to!string);

    // error on not enough funds on funding UTXO
    res = alice.openNewChannel(alice_pubkey,
        utxo, utxo_hash, Amount.MaxUnitSupply, Settle_10_Blocks, bob_pair.V);
    assert(res.error == ErrorCode.RejectedFundingUTXO);

    // error on not enough funds on funding UTXO for TX fees
    res = alice.openNewChannel(alice_pubkey,
        utxo, utxo_hash, utxo.output.value, Settle_10_Blocks, bob_pair.V);
    assert(res.error == ErrorCode.RejectedFundingUTXO);

    // error on not own funding UTXO
    res = bob.openNewChannel(bob_pubkey,
        utxo, utxo_hash, Amount(10_000), 1000, alice_pair.V);
    assert(res.error == ErrorCode.RejectedFundingUTXO);

    res = alice.openNewChannel(alice_pubkey,
        utxo, utxo_hash, Amount(10_000), 1000, bob_pair.V);
    assert(res.error == ErrorCode.None);

    error = factory.listener.waitUntilChannelState(res.value,
        ChannelState.Rejected);
    assert(error == ErrorCode.RejectedSettleTime, res.to!string);

    const chan_id_res = alice.openNewChannel(alice_pubkey,
        utxo, utxo_hash, Amount(10_000), Settle_10_Blocks, bob_pair.V);
    assert(chan_id_res.error == ErrorCode.None, chan_id_res.message);
    factory.listener.waitUntilChannelState(res.value, ChannelState.SettingUp);
    const chan_id = chan_id_res.value;

    // await funding transaction
    network.expectHeightAndPreImg(Height(9), network.blocks[0].header);
    const block_9 = node_1.getBlocksFrom(9, 1)[$ - 1];
    assert(block_9.txs.any!(tx => tx.hashFull() == chan_id));

    // wait for the parties to detect the funding tx
    alice.waitForChannelOpen(alice_pubkey, chan_id);
    bob.waitForChannelOpen(bob_pubkey, chan_id);
    factory.listener.waitUntilChannelState(chan_id, ChannelState.Open);

    // test what happens trying to open a new channel with the same funding tx
    res = alice.openNewChannel(alice_pubkey, utxo, utxo_hash, Amount(10_000),
        Settle_10_Blocks, bob_pair.V);
    assert(res.error == ErrorCode.DuplicateChannelID, res.to!string);

    // test some update signer error cases
    auto sig_res = alice.requestSettleSig(bob_pubkey, alice_pubkey, Hash.init, 0);
    assert(sig_res.error == ErrorCode.InvalidChannelID, sig_res.to!string);

    sig_res = alice.requestUpdateSig(bob_pubkey, alice_pubkey, Hash.init, 0);
    assert(sig_res.error == ErrorCode.InvalidChannelID, sig_res.to!string);

    /*** test invalid payment proposals ***/

    // mismatching version byte
    OnionPacket onion = { version_byte : ubyte.max };
    auto pay_res = alice.proposePayment(bob_pubkey, alice_pubkey, Hash.init, 0, Hash.init, Amount.init,
        Height.init, onion, PublicNonce.init, Height.init);
    assert(pay_res.error == ErrorCode.VersionMismatch, pay_res.to!string);

    // invalid channel ID
    onion.version_byte = 0;
    pay_res = alice.proposePayment(bob_pubkey, alice_pubkey, Hash.init, 0, Hash.init, Amount.init,
        Height.init, onion, PublicNonce.init, Height.init);
    assert(pay_res.error == ErrorCode.InvalidChannelID, pay_res.to!string);

    // ephemeral pk is invalid
    pay_res = alice.proposePayment(bob_pubkey, alice_pubkey, chan_id, 0, Hash.init, Amount.init,
        Height.init, onion, PublicNonce.init, Height.init);
    assert(pay_res.error == ErrorCode.InvalidOnionPacket, pay_res.to!string);

    // onion packet cannot be decrypted
    onion.ephemeral_pk = Scalar.random().toPoint();
    pay_res = alice.proposePayment(bob_pubkey, alice_pubkey, chan_id, 0, Hash.init, Amount.init,
        Height.init, onion, PublicNonce.init, Height.init);
    assert(pay_res.error == ErrorCode.InvalidOnionPacket, pay_res.to!string);

    // invalid next channel ID
    Hop[] path = [
        Hop(Point(alice_pair.V[]), chan_id, Amount(10)),
        Hop(Scalar.random().toPoint(), hashFull(2), Amount(10))];
    Amount total_amount;
    Height use_lock_height;
    Point[] shared_secrets;
    onion = createOnionPacket(hashFull(42), Amount(100), path,
        total_amount, use_lock_height, shared_secrets);
    pay_res = alice.proposePayment(bob_pubkey, alice_pubkey, chan_id, 0, hashFull(42), total_amount,
        use_lock_height, onion, PublicNonce.init, Height.init);
    assert(pay_res.error == ErrorCode.InvalidChannelID, pay_res.to!string);

    /*** test invalid update proposals ***/

    // invalid channel ID
    auto upd_res = alice.proposeUpdate(bob_pubkey, alice_pubkey, Hash.init, 0, null, null,
        PublicNonce.init, Height.init);
    assert(upd_res.error == ErrorCode.InvalidChannelID, upd_res.to!string);

    // invalid height
    upd_res = alice.proposeUpdate(bob_pubkey, alice_pubkey, chan_id, 0, null, null,
        PublicNonce.init, Height(100));
    assert(upd_res.error == ErrorCode.MismatchingBlockHeight, upd_res.to!string);
}

/// test listener API and payment success / failures
unittest
{
    static class RejectingFlashNode : TestFlashNode
    {
        mixin ForwardCtor!();

        ///
        public override Result!PublicNonce proposePayment (PublicKey sender_pk,
            PublicKey recv_pk, /* in */ Hash chan_id,
            /* in */ uint seq_id, /* in */ Hash payment_hash,
            /* in */ Amount amount, /* in */ Height lock_height,
            /* in */ OnionPacket packet, /* in */ PublicNonce peer_nonce,
            /* in */ Height height) @trusted
        {
            if (seq_id >= 2)
                return Result!PublicNonce(ErrorCode.Unknown, "I'm a bad node");
            else
                return super.proposePayment(sender_pk, recv_pk, chan_id, seq_id,
                    payment_hash, amount, lock_height, packet, peer_nonce,
                    height);
        }
    }

    TestConf conf = { payout_period : 100 };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();

    foreach (idx, tx; txs)
    {
        node_1.putTransaction(tx);
        network.expectHeightAndPreImg(Height(idx + 1), network.blocks[0].header);
    }

    auto factory = new FlashNodeFactory!()(network.getRegistry());
    scope (exit) factory.shutdown();
    scope (failure) factory.printLogs();

    const alice_pair = Pair(WK.Keys[0].secret, WK.Keys[0].secret.toPoint);
    const bob_pair = Pair(WK.Keys[1].secret, WK.Keys[1].secret.toPoint);
    const charlie_pair = Pair(WK.Keys[2].secret, WK.Keys[2].secret.toPoint);

    // workaround to get a handle to the node from another registry's thread
    const string address = format("Validator #%s (%s)", 0, genesis_validator_keys[0].address);

    FlashConfig alice_conf = { enabled : true,
        min_funding : Amount(1000),
        max_funding : Amount(100_000_000),
        min_settle_time : 0,
        max_settle_time : 100,
        listener_address : factory.ListenerAddress,
        max_retry_time : 4.seconds,
        max_retry_delay : 10.msecs,
    };

    auto alice = factory.create(alice_pair, alice_conf, address);
    auto bob = factory.create!RejectingFlashNode(bob_pair, address);
    auto charlie = factory.create(charlie_pair, address);

    const alice_pubkey = PublicKey(alice_pair.V);
    const bob_pubkey = PublicKey(bob_pair.V);
    const charlie_pubkey = PublicKey(charlie_pair.V);

    // 0 blocks settle time after trigger tx is published (unsafe)
    const Settle_1_Blocks = 0;

    // the utxo the funding tx will spend (only relevant to the funder)
    const utxo = UTXO(0, txs[0].outputs[0]);
    const utxo_hash = UTXO.getHash(hashFull(txs[0]), 0);
    const chan_id_res = alice.openNewChannel(alice_pubkey,
        utxo, utxo_hash, Amount(10_000), Settle_1_Blocks, bob_pair.V);
    assert(chan_id_res.error == ErrorCode.None, chan_id_res.message);
    const chan_id = chan_id_res.value;
    factory.listener.waitUntilChannelState(chan_id, ChannelState.SettingUp);

    // await funding transaction
    network.expectHeightAndPreImg(Height(9), network.blocks[0].header);
    const block_9 = node_1.getBlocksFrom(9, 1)[$ - 1];
    assert(block_9.txs.any!(tx => tx.hashFull() == chan_id));

    // wait for the parties to detect the funding tx
    alice.waitForChannelOpen(alice_pubkey, chan_id);
    bob.waitForChannelOpen(bob_pubkey, chan_id);
    factory.listener.waitUntilChannelState(chan_id, ChannelState.Open);

    auto update_tx = alice.getPublishUpdateIndex(alice_pubkey, chan_id, 0);

    /* do some off-chain transactions */
    auto inv_1 = bob.createNewInvoice(bob_pubkey, Amount(5_000), time_t.max,
        "payment 1");
    alice.payInvoice(alice_pubkey, inv_1.value);

    alice.waitForUpdateIndex(alice_pubkey, chan_id, 2);
    bob.waitForUpdateIndex(bob_pubkey, chan_id, 2);

    auto res = factory.listener.waitUntilNotified(inv_1.value);
    assert(res == ErrorCode.None);  // should succeed

    auto inv_2 = bob.createNewInvoice(bob_pubkey, Amount(1_000), time_t.max,
        "payment 2");
    alice.payInvoice(alice_pubkey, inv_2.value);

    res = factory.listener.waitUntilNotified(inv_2.value);
    assert(res != ErrorCode.None);  // should have failed

    auto inv_3 = charlie.createNewInvoice(charlie_pubkey, Amount(1_000),
        time_t.max, "charlie");
    alice.payInvoice(alice_pubkey, inv_3.value);

    res = factory.listener.waitUntilNotified(inv_3.value);
    assert(res == ErrorCode.PathNotFound);
}

/// test listener API rejecting channels
unittest
{
    /// Rejects opening new channels
    static class RejectingFlashListener : FlashListener
    {
        mixin ForwardCtor!();

        public override string onRequestedChannelOpen (PublicKey pk,
            ChannelConfig conf)
        {
            return "I don't like this channel";
        }
    }

    TestConf conf = { payout_period : 100 };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();

    foreach (idx, tx; txs)
    {
        node_1.putTransaction(tx);
        network.expectHeightAndPreImg(Height(idx + 1), network.blocks[0].header);
    }

    auto factory = new FlashNodeFactory!RejectingFlashListener(network.getRegistry());
    scope (exit) factory.shutdown();
    scope (failure) factory.printLogs();

    const alice_pair = Pair(WK.Keys[0].secret, WK.Keys[0].secret.toPoint);
    const bob_pair = Pair(WK.Keys[1].secret, WK.Keys[1].secret.toPoint);
    const charlie_pair = Pair(WK.Keys[2].secret, WK.Keys[2].secret.toPoint);

    const alice_pubkey = PublicKey(alice_pair.V);

    // workaround to get a handle to the node from another registry's thread
    const string address = format("Validator #%s (%s)", 0, genesis_validator_keys[0].address);

    FlashConfig alice_conf = { enabled : true,
        min_funding : Amount(1000),
        max_funding : Amount(100_000_000),
        min_settle_time : 0,
        max_settle_time : 100,
        listener_address : factory.ListenerAddress,
        max_retry_time : 4.seconds,
        max_retry_delay : 10.msecs,
    };

    auto alice = factory.create(alice_pair, alice_conf, address);
    auto bob = factory.create(bob_pair, address);
    auto charlie = factory.create(charlie_pair, address);

    // 0 blocks settle time after trigger tx is published (unsafe)
    const Settle_1_Blocks = 0;

    // the utxo the funding tx will spend (only relevant to the funder)
    const utxo = UTXO(0, txs[0].outputs[0]);
    const utxo_hash = UTXO.getHash(hashFull(txs[0]), 0);
    const chan_id_res = alice.openNewChannel(alice_pubkey,
        utxo, utxo_hash, Amount(10_000), Settle_1_Blocks, bob_pair.V);
    assert(chan_id_res.error == ErrorCode.None, chan_id_res.message);
    const chan_id = chan_id_res.value;

    auto error = factory.listener.waitUntilChannelState(chan_id,
        ChannelState.Rejected);
    assert(error == ErrorCode.UserRejectedChannel);
}
