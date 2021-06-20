/*******************************************************************************

    Contains utilities to be used by tests to easily set up test environments

    Since our business code is decoupled from our network code,
    thanks to the `vibe.web.rest` generator, we can fairly naturally make
    unittests for network behavior.
    By using the `localrest` library, we assign each node to a thread and use
    an RPC-style approach to call functions.
    This is non-deterministic, but models a real-life behaviour better.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.Base;

version (unittest):

import agora.api.FullNode : NodeInfo, NetworkState;
import agora.api.Validator : ValidatorAPI = API, Identity;
import agora.common.Amount;
import agora.common.BanManager;
import agora.common.BitField;
import agora.common.Config;
import agora.common.ManagedDatabase;
import agora.common.Metadata;
import agora.common.Set;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.data.Enrollment;
import agora.consensus.data.genesis.Test;
import agora.consensus.data.Params;
import agora.consensus.data.PreImageInfo;
import agora.consensus.data.ValidatorBlockSig;
import agora.consensus.data.Transaction;
import agora.consensus.EnrollmentManager;
import agora.consensus.Fee;
import agora.consensus.protocol.Data;
import agora.consensus.protocol.Nominator;
import agora.consensus.Quorum;
import agora.consensus.SCPEnvelopeStore;
import agora.consensus.state.UTXOSet;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.network.Client;
import agora.network.Clock;
import agora.network.Manager;
import agora.node.BlockStorage;
import agora.node.FullNode;
import agora.node.Ledger;
import agora.node.TransactionPool;
import agora.node.Validator;
import agora.registry.API;
import agora.registry.Server;
import agora.utils.Log;
import agora.utils.PrettyPrinter;
public import agora.utils.Utility : retryFor;
import agora.utils.Workarounds;

import scpd.types.Stellar_SCP;

static import geod24.LocalRest;
import geod24.Registry;

import std.array;
import std.exception;
import std.range;

import core.atomic : atomicLoad, atomicStore;
import core.exception;
import core.runtime;
import core.stdc.time;
import core.thread;

/* The following imports are frequently needed in tests */

public import agora.common.Types;
 // Contains utilities for testing, e.g. `retryFor`
public import agora.utils.Test;
// `core.time` provides duration-related utilities, used e.g. for `retryFor`
public import core.time;
// Useful to express complex pipeline simply
public import std.algorithm;
// Provides `to`, a template to convert anything to anything else
public import std.conv;
// `format` is often used to provide useful error messages
public import std.format;
// Range utilities are often used in combination with `std.algorithm`
public import std.range;
// To print messages to the screen while debugging a test
public import std.stdio;
// Make inheriting much easier
public import std.traits : Parameters;

// Convenience constants
public const size_t GenesisValidators = GenesisBlock.header.enrollments.count();
public const uint GenesisValidatorCycle = GenesisBlock
    .header.enrollments[0].cycle_length;

shared static this ()
{
    Runtime.extendedModuleUnitTester = &customModuleUnitTester;
}

/// Workaround for issue likely related to dub #225,
/// expects a main() function and invokes it after unittesting.
void main () { }

void testAssertHandler (string file, ulong line, string msg) nothrow
{
    // `std.typecons` test an assert failure, so handle it explicitly
    static immutable Typecons = "std/typecons.d";
    if (file.length >= Typecons.length && file[$ - Typecons.length .. $] == Typecons)
        throw new AssertError(msg, file, line);

    try
    {
        scope output = stdout.lockingTextWriter();
        output.formattedWrite(
            "================================ ASSERT HANDLER ===============================\n");
        output.formattedWrite!"[%s:%s] Assertion thrown during test: %s\n"
            (file, line, msg);

        // Print stack trace starting from the failing line
        scope trace = defaultTraceHandler(null);
        bool findStart = false;
        foreach (traceLine; trace)
        {
            if (!findStart)
            {
                if (traceLine.canFind("_d_assert"))
                    findStart = true;
                continue;
            }
            output.formattedWrite("%s\n", traceLine);
        }

        // We only want to print the logs if we're in the main thread,
        // which means we are unittests non-`agora.test` modules.
        // Modules in `agora.test` use network tests and they will call `printLogs`
        // on failure for each nodes themselves
        // See https://github.com/bosagora/agora/issues/1972
        if (Thread.getThis().isMainThread())
            CircularAppender!()().print(output);
        stdout.flush();
    }
    catch (Exception exc)
    {
        scope exc_name = typeid(exc).name;
        printf("Could not print thread logs because of %.*s (%.*s:%llu): %.*s\n",
            cast(int) exc_name.length, exc_name.ptr,
            cast(int) file.length, file.ptr, line, cast(int) msg.length, msg.ptr);
    }
    // We still want a stack trace, so throw anyway
    throw new AssertError(msg, file, line);
}

/// Skip printing out per-node logs ony agora/test/* failures
shared bool no_logs;

/// Custom unnitest runner as a workaround for multi-threading issue:
/// Agora unittests spawn threads, which allocate. The Ocean tests
/// inspect GC stats for memory allocation changes, and potentially fail
/// if during such a test a runaway Agora unnittest child thread allocates.
/// Workaround: Don't run ocean submodule unittests
private UnitTestResult customModuleUnitTester ()
{
    import std.parallelism;
    import std.process;
    import std.string;
    import std.uni;
    import std.conv;
    import core.atomic;
    import core.sync.semaphore;
    import core.thread.osthread;

    // by default emit only errors during unittests.
    // can be re-set by calling code.
    Log.root.level(Log.root.Level.Error, true);

    // display the thread's log buffer when an assertion fails during a test
    assertHandler = &testAssertHandler;

    //
    const chatty = ("dchatty" in environment) ?
        to!bool(environment["dchatty"]) : false;
    no_logs = ("dnologs" in environment) ?
        to!bool(environment["dnologs"]) : false;
    const all_single_threaded = ("dsinglethreaded" in environment) ?
        to!bool(environment["dsinglethreaded"]) : false;
    const should_fail_early = ("dfailearly" in environment) ?
        to!bool(environment["dfailearly"]) : true;
    auto filter = environment.get("dtest").toLower();
    size_t filtered;

    // can't use ModuleInfo[], opApply returns temporaries..
    struct ModTest
    {
        string name;
        void function() test;
    }

    ModTest[] single_threaded;
    ModTest[] parallel_tests;
    ModTest[] heavy_tests;

    foreach (ModuleInfo* mod; ModuleInfo)
    {
        if (mod is null)
            continue;

        auto fp = mod.unitTest;
        if (fp is null)
            continue;

        if (mod.name.startsWith("agora") ||
            mod.name.startsWith("scpd"))
        {
            if (filter.length > 0 &&
                !canFind(mod.name.toLower(), filter.save))
            {
                filtered++;
                continue;
            }

            // this test checks GC usage stats before / after tests,
            // but other threads can change the outcome of the GC usage stats
            if (all_single_threaded || mod.name == "agora.common.Serializer")
                single_threaded ~= ModTest(mod.name, fp);
            else if (mod.name == "agora.test.ManyValidators")
                heavy_tests ~= ModTest(mod.name, fp);
            else
                // due to problems with the parallelism test,
                // the test is performed with single threads
                version (Windows)
                    single_threaded ~= ModTest(mod.name, fp);
                else
                    parallel_tests ~= ModTest(mod.name, fp);
        }
    }

    shared size_t executed;
    shared size_t passed;

    bool runTest (ModTest mod)
    {
        atomicOp!"+="(executed, 1);
        try
        {
            import std.datetime.stopwatch : AutoStart, StopWatch;

            if (chatty)
            {
                auto output = stdout.lockingTextWriter();
                output.formattedWrite("Unittesting %s", mod.name);
                stdout.flush();
            }
            auto sw = StopWatch(AutoStart.yes);
            mod.test();
            sw.stop();
            if (chatty)
            {
                auto output = stdout.lockingTextWriter();
                output.formattedWrite(" (took %s)\n", sw.peek());
                stdout.flush();
            }

            atomicOp!"+="(passed, 1);
            return true;
        }
        catch (Throwable ex)
        {
            auto output = stdout.lockingTextWriter();
            output.formattedWrite("Module tests failed: %s\n", mod.name);
            output.formattedWrite("%s\n", ex);
            // print logs of the work thread
            CircularAppender!()().print(output);
            stdout.flush();
        }
        return false;
    }

    // Run single-threaded tests
    bool failed_early;
    foreach (mod; single_threaded)
        if (!runTest(mod))
            if ((failed_early = should_fail_early) == true)
                break;

    auto available_cores = new Semaphore(totalCPUs);
    auto finished_tasks_num = new Semaphore(0);
    // we cannot use phobos' parallel function, as that function will not
    // re-initialize static variables at the start of a new task
    void runInParallel (ModTest[] parallel_tests)
    {
        class WorkThread : Thread
        {
            ModTest test;
            this (ModTest test)
            {
                this.test = test;
                super(&this.run);
            }

            void run ()
            {
                scope (exit)
                {
                    available_cores.notify();
                    finished_tasks_num.notify();
                }
                runTest(this.test);
            }
        }

        while (parallel_tests.length)
        {
            auto test = parallel_tests.front;
            parallel_tests.popFront();

            // wait for a core to become available
            available_cores.wait();

            (new WorkThread(test)).start();
        }
    }

    if (!failed_early)
    {
        runInParallel(parallel_tests);
        runInParallel(heavy_tests);

        //waiting for all parallel tasks to finish
        iota(parallel_tests.length + heavy_tests.length).each!(x => finished_tasks_num.wait());
    }

    UnitTestResult result = { executed : executed, passed : passed };
    if (filtered > 0)
        writefln("Ran %s/%s tests (%s filtered)", result.executed,
            result.executed + filtered, filtered);
    if (failed_early)
    {
        writefln("Single threaded test failed early. Only %s/%s tests have been run",
                 executed, single_threaded.length + parallel_tests.length + heavy_tests.length);
    }

    //result.summarize = true;
    result.runMain = false;
    return result;
}

/// A custom serializer for LocalRest
public struct Serializer
{
    import agora.serialization.Serializer;

    static immutable(ubyte)[] serialize (T) (auto ref T value)
    {
        // `serializeFull` should be `@safe`, but `assumeUnique` is not
        return ((arr) @trusted => assumeUnique(arr))(serializeFull(value));
    }

    static QT deserialize (QT) (in ubyte[] data) @trusted
    {
        return deserializeFull!QT(data);
    }
}

/// A different default serializer from `LocalRest` for `RemoteAPI`
public alias RemoteAPI (APIType) = geod24.LocalRest.RemoteAPI!(APIType, Serializer);

/*******************************************************************************

    Task manager backed by LocalRest's event loop.

*******************************************************************************/

public class LocalRestTaskManager : ITaskManager
{
    static import geod24.LocalRest;

    /***************************************************************************

        Run an asynchronous task in LocalRest's event loop.

        Params:
            dg = the delegate the task should run

    ***************************************************************************/

    public override void runTask (void delegate() nothrow dg) nothrow
    {
        this.tasks_started++;
        geod24.LocalRest.runTask(dg);
    }

    /***************************************************************************

        Suspend the current task for the given duration

        Params:
            dur = the duration for which to suspend the task for

    ***************************************************************************/

    public override void wait (Duration dur) nothrow
    {
        geod24.LocalRest.sleep(dur);
    }

    /***************************************************************************

        Run an asynchronous task after a given time in LocalRest's

        The task will first run after the given `timeout`, and
        can either repeat or run only once (the default).
        Works similarly to Vibe.d's `setTimer`.

        Params:
            timeout = Determines the minimum amount of time that elapses before
                the timer fires.
            dg = This delegate will be called when the timer fires.
            periodic = Specifies if the timer fires repeatedly or only once.

        Return:
           An `ITimer` interface with the ability to control the timer

    ***************************************************************************/

    public override ITimer setTimer (Duration timeout, void delegate() dg,
        Periodic periodic = Periodic.No) nothrow
    {
        this.tasks_started++;
        return new LocalRestTimer(geod24.LocalRest.setTimer(timeout, dg,
            periodic));
    }
}

/*******************************************************************************

    LocalRest only timer (for unittests)

*******************************************************************************/

private final class LocalRestTimer : ITimer
{
    import LocalRest = geod24.LocalRest;

    private LocalRest.Timer timer;

    public this (LocalRest.Timer timer) @safe nothrow
    {
        this.timer = timer;
    }

    /// Ditto
    public override void stop () @safe nothrow
    {
        this.timer.stop();
    }
}

/// A ban manager not loading and dumping
public class TestBanManager : BanManager
{
    /// Ctor (exclude the 'Logger' default argument)
    public this (Parameters!(BanManager.__ctor)[0 .. 3] args)
    {
        super(args);
    }

    /// no-op
    public override void load () { }

    /// no-op
    public override void dump () { }
}

/// Nominator with custom rules for when blocks should be nominated
public extern (C++) class TestNominator : Nominator
{
extern(D):
    /// test start time
    protected ulong test_start_time;

    ///
    public this (Parameters!(Nominator.__ctor) args,
        ulong test_start_time)
    {
        super(args);
        this.test_start_time = test_start_time;
    }

}

/// We use a pair of (key, client) rather than a hashmap client[key],
/// since we want to know the order of the nodes which were configured
/// in the makeTestNetwork() call.
public struct NodePair
{
    ///
    public Address address;

    ///
    public RemoteAPI!TestAPI client;

    /// the adjustable local clock time for this node.
    /// This does not affect request timeouts and is only
    /// used in the Nomination protocol.
    private shared(TimePoint)* cur_time;

    ///
    public TestAPI api;

    alias api this;

    /// Get the current clock time
    @property TimePoint time () @trusted @nogc nothrow
    {
        return atomicLoad(*this.cur_time);
    }

    /// Set the new time
    @property void time (TimePoint new_time) @trusted @nogc nothrow
    {
        atomicStore(*this.cur_time, new_time);
    }
}

/*******************************************************************************

    Used by unittests to send messages to individual nodes.
    This class is instantiated once per unittest.

*******************************************************************************/

public class TestAPIManager
{
    /// Test configuration
    protected TestConf test_conf;

    /// Used by the unittests in order to directly interact with the nodes,
    /// without trying to handshake or do any automatic network discovery.
    /// Also kept here to avoid any eager garbage collection.
    public NodePair[] nodes;

    /// Contains the initial blockchain state of all nodes
    public immutable(Block)[] blocks;

    /// Start time of the tests
    public const TimePoint test_start_time;

    /// The initial clock time of every spawned node. Note that if there were
    /// any extra blocks loaded (`blocks` in the ctor) then the initial time
    /// will be test_start_time + (last_height * block_interval)
    protected TimePoint initial_time;

    /// convenience: returns a random-access range which lets us access clients
    auto clients ()
    {
        return nodes.map!(np => np.client);
    }

    /// Registry holding the nodes
    protected Registry!TestAPI reg;

    /// Registry holding the name registries
    protected Registry!NameRegistryAPI nreg;

    ///
    public this (immutable(Block)[] blocks, TestConf test_conf,
        TimePoint test_start_time)
    {
        this.test_conf = test_conf;
        this.blocks = blocks;
        this.test_start_time = test_start_time;
        this.initial_time = test_start_time;
        this.reg.initialize();
        this.nreg.initialize();
        this.createNameRegistry();
    }


    /***************************************************************************

        Returns:
            A pointer to the network registry

    ***************************************************************************/

    public Registry!TestAPI* getRegistry ()
    {
        return &this.reg;
    }

    /***************************************************************************

        Sets the clock time to the expected clock time to produce a block at
        the given height, and verifies that the nodes have generated a block
        at the given block height.

        The overload allows passing a subset of nodes indices to verify the
        block heights for only these nodes. Note that the clock time is adjusted
        for all nodes (this is what most tests expect).

        Params:
            height = the expected block height
            timeout = the request timeout to each node

    ***************************************************************************/

    public void expectHeight (Height height, Duration timeout = 10.seconds,
        string file = __FILE__, int line = __LINE__)
    {
        this.expectHeight(iota(this.clients.length), height, timeout,
            file, line);
    }

    /// Ditto
    public void expectHeight (Idxs)(Idxs clients_idxs, Height height,
        Duration timeout = 10.seconds,
        string file = __FILE__, int line = __LINE__)
    {
        static assert (isInputRange!Idxs);

        this.setTimeFor(height);
        clients_idxs.each!(idx =>
            retryFor(clients[idx].getBlockHeight() == height, timeout,
                format("Node %s has block height %s. Expected: %s",
                    idx, clients[idx].getBlockHeight(), height), file, line));
    }

    /***************************************************************************

        Checks the needed pre-images are revealed, sets the clock time to the
        expected clock time to produce a block at the given height, and verifies
        that the nodes have generated a block at the given block height.

        The overload allows passing a subset of node indices to verify the block
        heights for only these nodes. Note that the clock time is adjusted
        for all nodes (this is what most tests expect).

        Params:
            height = the expected block height
            enroll_header = the header which contains enrollment information
            timeout = the request timeout to each node

    ***************************************************************************/

    public void expectHeightAndPreImg (Height height,
        const(BlockHeader) enroll_header = GenesisBlock.header,
        Duration timeout = 10.seconds,
        string file = __FILE__, int line = __LINE__)
    {
        this.expectHeightAndPreImg(iota(GenesisValidators), height, enroll_header,
            timeout, file, line);
    }

    /// Ditto
    public void expectHeightAndPreImg (Idxs)(Idxs clients_idxs, Height height,
        const(BlockHeader) enroll_header = GenesisBlock.header,
        Duration timeout = 10.seconds,
        string file = __FILE__, int line = __LINE__)
    {
        static assert (isInputRange!Idxs);

        assert(height > enroll_header.height);
        waitForPreimages(clients_idxs, enroll_header.enrollments, height, timeout);
        this.expectHeight(clients_idxs, height, timeout, file, line);
    }

    /***************************************************************************

        Checks if all the nodes contain the given height of pre-images for
        the given enrollments.

        The overload allows passing a subset of nodes to verify the height
        for only these nodes.

        Params:
            enrolls = the enrollments whose pre-image will be checked
            height = the expected height of pre-images
            timeout = the request timeout to each node

    ***************************************************************************/

    public void waitForPreimages (const(Enrollment)[] enrolls, Height height,
        Duration timeout = 10.seconds,
        string file = __FILE__, int line = __LINE__)
    {
        this.waitForPreimages(iota(GenesisValidators), enrolls, height,
            timeout, file, line);
    }

    /// Ditto
    public void waitForPreimages (Idxs)(Idxs clients_idxs,
        const(Enrollment)[] enrolls, Height height,
        Duration timeout = 10.seconds,
        string file = __FILE__, int line = __LINE__)
    {
        static assert (isInputRange!Idxs);

        clients_idxs.each!(idx =>
            enrolls.enumerate.each!((idx_enroll, enroll) {
                if (clients_idxs.canFind(idx_enroll))
                    retryFor(this.clients[idx].getPreimage(enroll.utxo_key).height >= height,
                        timeout, format!"Client #%s has no preimage for client #%s at distance %s"
                            (idx, idx_enroll, height));
            }));
    }

    /***************************************************************************

        Set the new clock time for all node instances based on the block height.

        The overload allows passing a subset of nodes to simulate clock drift.

        Note that `synchronizeClocks()` must be called manually to adjust the
        net time clock offset of each node.

        Params:
            new_time = the new clock time

    ***************************************************************************/

    public void setTimeFor (Height height)
    {
        this.setTimeFor(this.nodes, height);
    }

    /// Ditto
    public void setTimeFor (Pairs)(Pairs pairs, Height height)
    {
        static assert (isInputRange!Pairs);

        const exp_time = test_start_time + this.getBlockTimeOffset(height);
        foreach (pair; pairs)
            pair.time = exp_time;
    }

    /***************************************************************************

        Synchronize the clocks of all nodes.

        Note that this is not done implicitly in `setTimeFor` as this might
        only synchronize the clocks for a subset of the passed clients.

    ***************************************************************************/

    public void synchronizeClocks ()
    {
        // calculate the network time offset based on the node's quorum set
        foreach (node; this.nodes)
            node.client.synchronizeClock();
    }

    /***************************************************************************

        Params:
            height = the requested block height

        Returns:
            the expected time_offset for the given block height

    ***************************************************************************/

    public TimePoint getBlockTimeOffset (Height height)
    {
        return height * this.test_conf.block_interval_sec;
    }

    /***************************************************************************

        Create a new node

        Params:
            conf = the configuration passed on to the Node constructor

    ***************************************************************************/

    public void createNewNode (Config conf, string file = __FILE__, int line = __LINE__)
    {
        if (conf.validator.enabled)
            this.addNewNode!TestValidatorNode(conf, file, line);
        else
            this.addNewNode!TestFullNode(conf, file, line);
    }

    /***************************************************************************

        Convenience templated function to be called from overriding classes

        Params:
          conf = The configuration for this node (usually forwarded from
                 within `createNewNode`)
          eArgs = The arguments `NodeType` has which are after `TestFullNode`'s
                  (or `TestValidatorNode`'s) constructor arguments.
          file = File this function is called for, forwarded to localrest for
                 better debugging output.
          line = Line this function is called for, forwarded to localrest for
                 better debugging output.

        Note:
          The "extra arguments" parameter, `eArgs`, makes a few assumptions
          which might not hold in the future, most importantly:
          - `TestFullNode` and `TestValidatorNode` have the same ctor args;
          - Arguments for `NodeType` are in the same order as its parent;

    ***************************************************************************/

    public TestAPI addNewNode (NodeType : TestAPI) (Config conf,
        Parameters!(NodeType.__ctor)[Parameters!(TestValidatorNode.__ctor).length .. $] eArgs,
        string file = __FILE__, int line = __LINE__)
    {
        auto time = new shared(TimePoint)(this.initial_time);
        auto api = RemoteAPI!TestAPI.spawn!NodeType(conf, &this.reg, &this.nreg,
            this.blocks, this.test_conf, time, eArgs,
            conf.node.timeout, file, line);

        foreach (ref interf; conf.interfaces)
        {
            this.reg.register(interf.address, api.listener());
            this.nodes ~= NodePair(interf.address, api, time, api);
        }
        return api;
    }

    /***************************************************************************

        Create a new name registry

    ***************************************************************************/

    public void createNameRegistry ()
    {
        auto registry = RemoteAPI!NameRegistryAPI.spawn!NameRegistry();
        this.nreg.register("name.registry", registry.ctrl.listener());
    }

    /***************************************************************************

        Start each of the nodes

        Params:
            count = Expected number of nodes

    ***************************************************************************/

    public void start ()
    {
        foreach (node; this.nodes)
        {
            // have to wait indefinitely as the constructor is
            // currently a slow routine, stalling the call to start().
            node.client.ctrl.withTimeout(0.msecs,
                (scope TestAPI api) {
                    api.start();
                });
        }
    }

    /***************************************************************************

        Shut down each of the nodes

        Params:
          printLogs = Whether or not to print nodes logs

    ***************************************************************************/

    public void shutdown (bool printLogs = false)
    {
        foreach (node; this.nodes)
            enforce(this.reg.unregister(node.address));

        /// Private functions used for `shutdown`
        static void shutdownWithLogs (Object node)
        {
            (cast(FullNode)node).shutdown();
            (cast(TestAPI)node).printLog();
        }
        static void shutdownSilent (Object node)
        {
            (cast(FullNode)node).shutdown();
        }

        foreach (ref node; this.nodes)
        {
            node.client.ctrl.shutdown(
                printLogs ? &shutdownWithLogs : &shutdownSilent);
            node.client = null;
        }

        this.nodes = null;

        scope name_registry = new RemoteAPI!NameRegistryAPI(
            this.nreg.locate("name.registry"));
        enforce(this.nreg.unregister("name.registry"));
        name_registry.ctrl.shutdown();
    }

    /***************************************************************************

        Restart a specific node

        This routine restarts the given `client`, making sure it gracefully
        shuts down then restart properly.

        Params:
          client = Reference to the client to restart

    ***************************************************************************/

    public void restart (scope RemoteAPI!TestAPI client)
    {
        client.ctrl.restart((Object node) { (cast(FullNode)node).shutdown(); });
        client.ctrl.withTimeout(0.msecs, (scope TestAPI api) { api.start(); });
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
            writefln("%s(%s): Node logs:\n", file, line);
            foreach (node; this.nodes)
            {
                try
                {
                    node.client.printLog();
                }
                catch (Exception ex)
                {
                    writefln("Could not print logs for node: %s", ex.message);
                }
            }
        }
    }

    /***************************************************************************

        Keep polling for nodes to reach discovery, up to 5 seconds.

        If network discovery isn't reached, it will throw an Error.

    ***************************************************************************/

    public void waitForDiscovery (Duration timeout = 5.seconds,
        string file = __FILE__, int line = __LINE__)
    {
        try
        {
            this.nodes.each!(node =>
                retryFor(node.client.getNodeInfo().ifThrown(NodeInfo.init)
                    .state == NetworkState.Complete,
                    timeout,
                    format("Node %s has not completed discovery after %s.",
                        node.address, timeout)));
        }
        catch (Error ex)  // better UX
        {
            ex.file = file;
            ex.line = line;
            throw ex;
        }
    }

    /***************************************************************************

        Add blocks up to the provided height

        This is a helper function to enable some common steps to getting blocks
            externalized during the Network Unit tests

        Params:
            height = the desired block height
            client_idxs = client indices for the participating validators

    ***************************************************************************/

    public void generateBlocks (Height height,
        string file = __FILE__, int line = __LINE__)
    {
        generateBlocks(iota(GenesisValidators), height, file, line);
    }

    /// Ditto
    public void generateBlocks (Idxs)(Idxs client_idxs, Height height,
        string file = __FILE__, int line = __LINE__)
    {
        static assert (isInputRange!Idxs);

        // Get the last block from the first client
        auto client = this.clients[client_idxs.front];
        const last_block = client.getBlock(client.getBlockHeight());

        // Call addBlock for each block to be externalised for these clients
        iota(height - last_block.header.height)
            .each!(_ => this.addBlock(client_idxs, file, line));
    }

     /**************************************************************************

        Add a block

        This is a helper function to perform the steps required to get a block
            externalized during the Network Unit tests

        Params:
            client_idxs = client indices for the participating validators

    ***************************************************************************/

    void addBlock (string file = __FILE__, int line = __LINE__)
    {
        addBlock(iota(0, GenesisValidators), file, line);
    }

    /// Ditto
    void addBlock (Idxs)(Idxs client_idxs,
        string file = __FILE__, int line = __LINE__)
    {
        static assert (isInputRange!Idxs);

        auto first_client = this.clients[client_idxs.front];
        const last_block = first_client.getBlock(first_client.getBlockHeight());

        // traget height will be one more than previous block
        Height target_height = last_block.header.height + 1;

        // Get spendables from last block
        auto spendables = last_block.spendable().array;

        // Show the last block if not enough spendables
        assert(spendables.length >= 1,
            format!"[%s:%s] No spendables in block:\n%s"
                (file, line, prettify(last_block)));

        // Send transaction to the first client
        spendables.takeExactly(1)
            .map!(txb => txb.sign())
            .each!(tx => first_client.putTransaction(tx));

        // Get preimage height from enrollment to this next block
        auto enrolled_height = target_height <= GenesisValidatorCycle ? 0
            : target_height - ((target_height - 1) % GenesisValidatorCycle) - 1;
        assert(enrolled_height % GenesisValidatorCycle == 0,
            format!"[%s:%s] Invalid enroll height calculated as %s for target height %s"
                (file, line, enrolled_height, target_height));
        // Check block is at target height for the participating clients
        const enroll_block = first_client.getBlock(enrolled_height);
        expectHeightAndPreImg(client_idxs, target_height,
            enroll_block.header, 10.seconds, file, line);
    }

    /***************************************************************************

        Enroll validator

        This is a helper function to enroll a validator and wait till
            other validators have the enroll on their pool

        Params:
            client_idx = the index of the client to enroll
            client_idxs = client indices for the participating validators

    ***************************************************************************/

    void enroll (size_t client_idx)
    {
        enroll(iota(GenesisValidators), client_idx);
    }

    /// Ditto
    void enroll (Idxs)(Idxs client_idxs, size_t client_idx,
        string file = __FILE__, int line = __LINE__)
    {
        static assert (isInputRange!Idxs);

        auto enroll = clients[client_idx].setRecurringEnrollment(true);
        client_idxs.each!(idx =>
            retryFor(this.clients[idx].getEnrollment(enroll.utxo_key) == enroll,
                5.seconds,
                format!"[%s:%s] Client #%s enrollment not in pool of client #%s"
                    (file, line, client_idx, idx)));
    }

    /***************************************************************************

        Assert all the nodes contain the same blocks

        This is a helper function to confirm all nodes have the same blocks
        Note that the `from` and `to` are reversed to enable default value

        Params:
            client_idxs = client indices for the nodes to be checked
            to = expected block height of the nodes
            from = start of range for comparing the blocks

    ***************************************************************************/

    void assertSameBlocks (Height to, Height from = Height(0),
        string file = __FILE__, int line = __LINE__)
    {
        assertSameBlocks(iota(GenesisValidators), to, from, file, line);
    }

    /// Ditto
    void assertSameBlocks (Idxs)(Idxs client_idxs, Height to,
        Height from = Height(0), string file = __FILE__, int line = __LINE__)
    {
        static assert (isInputRange!Idxs);
        const MaxBlocks = 1024;
        assert(to >= from,
            format!"[%s:%s] Please provide valid heights as params. Not %s .. %s"
            (file, line, from, to));

        client_idxs.each!(idx =>
            retryFor(Height(this.clients[idx].getBlockHeight()) == to,
                5.seconds,
                format!"[%s:%s] Expected height %s for client #%s not %s"
                    (file, line, to, idx,
                        this.clients[idx].getBlockHeight())));

        // Compare blocks one at a time
        iota(from, to + 1).each!(h =>
            retryFor(client_idxs.map!(idx =>
                this.clients[idx].getBlocksFrom(h, 1)).uniq().count() == 1, 5.seconds,
                format!"[%s:%s] Clients %s blocks are not all the same for block %s: %s"
                (file, line, client_idxs, h, client_idxs.fold!((s, i) =>
                    s ~ format!"\n\n========== Client #%s ==========%s"
                        (i, prettify(this.clients[i].getBlocksFrom(h, 1))))(""))));
    }
}

/*******************************************************************************

    Base class for `NetworkManager` used in unittests.
    This class is instantiated once per unittested node.

    The `NetworkManager` class is the mean used to communicate with other nodes.
    In regular build, it does network communication, but in unittests it should
    not do IO (or appear not to).

    In the current design, all nodes should be instantiated upfront,
    registered via `geod24.Registry`, and located by `getClient`.

*******************************************************************************/

public class TestNetworkManager : NetworkManager
{
    import agora.api.handler.Block;
    import agora.api.handler.PreImage;
    import agora.api.handler.Transaction;

    /// Remove this once `registerListener` is gone
    private string address;

    ///
    public Registry!TestAPI* registry;

    ///
    public Registry!NameRegistryAPI* nregistry;

    /// Constructor
    public this (Parameters!(NetworkManager.__ctor) args, string address,
                 Registry!TestAPI* reg, Registry!NameRegistryAPI* nreg)
    {
        super(args);
        this.registry = reg;
        this.nregistry = nreg;
        this.address = address;
    }

    ///
    protected final override TestAPI getClient (Address address,
        Duration timeout)
    {
        auto tid = this.registry.locate(address);
        if (tid != typeof(tid).init)
            return new RemoteAPI!TestAPI(tid, timeout);
        assert(0, "Trying to access node at address '" ~ address ~
               "' without first creating it");
    }

    ///
    public override RemoteAPI!NameRegistryAPI getNameRegistryClient (Address address, Duration timeout)
    {
        auto tid = this.nregistry.locate(address);
        if (tid != typeof(tid).init)
            return new RemoteAPI!NameRegistryAPI(tid, timeout);
        assert(0, "Trying to access name registry at address '" ~ address ~
               "' without first creating it");
    }

    /***************************************************************************

        Params:
            conf = ban manager config
            clock = clock instance
            data_dir = path to the data directory

        Returns:
            an instance of a TestBanManager

    ***************************************************************************/

    protected override TestBanManager getBanManager (in BanManager.Config conf,
        Clock clock, string data_dir)
    {
        return new TestBanManager(conf, clock, data_dir);
    }

    ///
    protected final override BlockExternalizedHandler getBlockExternalizedHandler
        (Address address)
    {
        assert(0, "Not supported");
    }

    ///
    protected final override PreImageReceivedHandler getPreimageReceivedHandler
        (Address address)
    {
        assert(0, "Not supported");
    }

    ///
    protected final override TransactionReceivedHandler getTransactionReceivedHandler
        (Address address)
    {
        assert(0, "Not supported");
    }
}

/*******************************************************************************

    API implemented by the test nodes runs by LocalRest

    This API inherits from ValidatorAPI, and simply adds a few functions that
    should not be public in a real-world scenario, but are needed in our test
    setup. Those functions trigger a specific action (e.g. `start`, `printLog`),
    or in rare cases are a way to force a node to take a specific action.

    However, adding a method here should be carefully considered, as most of the
    time, the prefered approach to test a specific behavior on a node would be
    to instantiate a different kind of node (derive from `TestFullNode` or
    `TestValidatorNode` and implement the desired behavior), as this approach
    will be localized to the test, instead of being available to every tests.

    Besides the current functions, extra functionalities that would fit in this
    interface would be machine state changes, e.g. `removeDisk`.

*******************************************************************************/

public interface TestAPI : ValidatorAPI
{
    /***************************************************************************

        Start the node

        The `FullNode` have a `start` method that is scheduled by the `main`
        function to start discovery / catchup, etc...
        Since our node is not instantiated through `main`, the `APIManager`
        will call this function directly after instantiating a new node.

    ***************************************************************************/

    public abstract void start ();

    /***************************************************************************

        Print out the contents of the log

        Each node logs to their own buffer in their own Thread, which is written
        to a circular buffer to save on memory.
        Calling this function will dump the content of the node's log buffer
        to stderr. `TestAPIManager` provides a convenient way to call
        this method for every node, and most tests will do this on test failure.

    ***************************************************************************/

    public abstract void printLog ();

    /***************************************************************************

        Clear a node's logs

        This forces a node to clear its logs, which can be useful for tests
        that produce a lot of logs, for example when many blocks are created.

    ***************************************************************************/

    public abstract void clearLog ();

    /***************************************************************************

        Toggle enrollment

        Check if the next enrollment is available or validator is not enrolled.
        Make a node to enroll when necessary.

        Params:
            doIt = if the enrollments will be renewed continuouly or not

        Returns:
            The `Enrollment` used to enroll with,
            or `Enrollment.init` if an enrollment is not possible

    ***************************************************************************/

    public abstract Enrollment setRecurringEnrollment (bool doIt);

    ///
    public QuorumConfig getQuorumConfig ();

    /// Get the active validator count for the current block height
    public ulong countActive (in Height height);

    /// Get the list of expected quorum configs
    public QuorumConfig[] getExpectedQuorums (in PublicKey[], Height);

    /***************************************************************************

        Synchronize the node's clock with the network

    ***************************************************************************/

    public void synchronizeClock ();

    /***************************************************************************

        Returns:
            the adjusted clock time taking into account the clock drift compared
            to the median value of the quorum set clock measurements

    ***************************************************************************/

    public TimePoint getNetworkTime ();

    /***************************************************************************

        Returns:
            true if the tx hash was at one point accepted to the tx pool,
            even if it was later removed (e.g. during block externalization)

    ***************************************************************************/

    public bool hasAcceptedTxHash (Hash tx_hash);

    /***************************************************************************

        Provides access to the state of the UTXO set

    ***************************************************************************/

    public UTXOPair[] getUTXOs (PublicKey owner);

    /// Ditto
    public UTXO getUTXO (Hash hash);

    /***************************************************************************

        Params:
            address = the address of node to query

        Returns:
            if `address` is banned or not

    ***************************************************************************/

    public bool isBanned (Address address);
}

/// Return type for `TestAPI.getUTXOs`
public struct UTXOPair
{
    ///
    public Hash hash;

    ///
    public UTXO utxo;
}

/// Contains routines which are implemented by both TestFullNode and
/// TestValidator. Used because TestValidator inherits from Validator but
/// cannot inherit from TestFullNode, as it already inherits from Validator class
/// (multiple-inheritance is not supported in D)
private mixin template TestNodeMixin ()
{
    ///
    protected Registry!TestAPI* registry;
    ///
    protected Registry!NameRegistryAPI* nregistry;

    /// pointer to the unittests-adjusted clock time
    protected shared(TimePoint)* cur_time;

    /// test start time
    protected ulong test_start_time;

    /// All txs which were at one point accepted into the tx pool
    protected Set!Hash accepted_txs;

    /// Blocks to preload into the memory storage
    private immutable(Block)[] blocks;

    ///
    public override void start ()
    {
        super.start();
    }

    /// Prints out the log contents for this node
    public override void printLog ()
    {
        auto output = stdout.lockingTextWriter();
        output.formattedWrite("Log for node: %s\n", this.config.interfaces[0].address);
        output.put("======================================================================\n");
        CircularAppender!()().print(output);
        output.put("======================================================================\n\n");
        stdout.flush();
    }

    ///
    public override void clearLog ()
    {
        CircularAppender!()().clear();
    }

    protected override IBlockStorage makeBlockStorage () @system
    {
        return new MemBlockStorage(this.blocks);
    }

    protected override ManagedDatabase makeStateDB ()
    {
        return new ManagedDatabase(":memory:");
    }

    protected override ManagedDatabase makeCacheDB ()
    {
        return new ManagedDatabase(":memory:");
    }

    /// Used by the node
    public override Metadata makeMetadata () @system
    {
        return new MemMetadata();
    }

    /// Return a LocalRest-backed task manager
    protected override ITaskManager makeTaskManager ()
    {
        return new LocalRestTaskManager();
    }

    /// Return an instance of the custom TestNetworkManager
    protected override NetworkManager makeNetworkManager (
        Metadata metadata, ITaskManager taskman, Clock clock)
    {
        assert(taskman !is null);
        return new TestNetworkManager(
            this.config, metadata, taskman, clock,
            this.config.interfaces[0].address, this.registry, this.nregistry);
    }

    /// Return an enrollment manager backed by an in-memory SQLite db
    protected override EnrollmentManager makeEnrollmentManager ()
    {
        return new EnrollmentManager(this.stateDB, this.cacheDB,
            this.config.validator.key_pair, this.params);
    }

    /// Get the active validator count for the current block height
    public override ulong countActive (in Height height)
    {
        return this.enroll_man.validator_set.countActive(height);
    }

    /// Manually initiate a clock synchronization event
    public override void synchronizeClock ()
    {
        this.clock.synchronize();
    }

    /// Return the adjusted clock time
    public override TimePoint getNetworkTime ()
    {
        return this.clock.networkTime();
    }

    /***************************************************************************

        Overrides base function to keep statistics about accepted txs.

    ***************************************************************************/

    public override void putTransaction (Transaction tx) @safe
    {
        super.putTransaction(tx);
        const tx_hash = tx.hashFull();
        if (tx_hash !in this.accepted_txs &&
            this.pool.hasTransactionHash(tx_hash))
            this.accepted_txs.put(tx_hash);
    }

    /***************************************************************************

        Returns:
            true if the tx hash was at one point accepted to the tx pool,
            even if it was later removed (e.g. during block externalization)

    ***************************************************************************/

    public bool hasAcceptedTxHash (Hash tx_hash)
    {
        return !!(tx_hash in this.accepted_txs);
    }

    ///
    public override UTXOPair[] getUTXOs (PublicKey owner)
    {
        return this.utxo_set.getUTXOs(owner).byKeyValue
            .map!((pair) => UTXOPair(pair.key, pair.value)).array;
    }

    ///
    public override UTXO getUTXO (Hash hash)
    {
        UTXO result;
        if (!this.utxo_set.peekUTXO(hash, result))
            throw new Exception(format("UTXO not found: %s", hash));
        return result;
    }

    /// Check if an address is banned
    public override bool isBanned (Address address)
    {
        return this.network.getBanManager().isBanned(address);
    }
}

///
public class TestClock : Clock
{
    ///
    private shared(TimePoint)* cur_time;

    ///
    public this (ITaskManager taskman, GetNetTimeOffset getNetTimeOffset,
        shared(TimePoint)* cur_time)
    {
        super(getNetTimeOffset,
            (Duration duration, void delegate() cb) nothrow @trusted
                { taskman.setTimer(duration, cb, Periodic.Yes); });
        this.cur_time = cur_time;
    }

    ///
    public override TimePoint localTime ()
    {
        return atomicLoad(*this.cur_time);
    }

    /// we manually sync the clocks in the tests, not using the timer
    public override void startSyncing () @safe nothrow
    {

    }
}

/// A FullNode which also implements test routines in TestAPI
public class TestFullNode : FullNode, TestAPI
{
    ///
    mixin TestNodeMixin!();

    ///
    public this (Config config, Registry!TestAPI* reg, Registry!NameRegistryAPI* nreg,
        immutable(Block)[] blocks, in TestConf test_conf, shared(TimePoint)* cur_time)
    {
        this.registry = reg;
        this.nregistry = nreg;
        this.blocks = blocks;
        this.cur_time = cur_time;
        this.test_start_time = *cur_time;
        super(config);
    }

    /// Provides a unittest-adjusted clock source for the node
    protected override TestClock makeClock (ITaskManager taskman)
    {
        return new TestClock(this.taskman,
            (out long time_offset) { return true; }, this.cur_time);
    }

    /// ditto
    public override Enrollment setRecurringEnrollment (bool doIt)
    {
        assert(0);
    }

    /// FullNode does not implement this
    public override Identity getPublicKey (PublicKey key = PublicKey.init) @safe
    {
        // NetworkManager assumes that if key == PublicKey.init,
        // we are *not* a Validator node, treated as a FullNode instead.
        return Identity.init;
    }

    /// FullNode does not implement this
    public override void receiveEnvelope (SCPEnvelope envelope) @safe
    {
        assert(0);
    }

    /// ditto
    public override void receiveBlockSignature (ValidatorBlockSig block_sig) @safe
    {
        assert(0);
    }

    /// ditto
    public override QuorumConfig getQuorumConfig ()
    {
        assert(0);
    }

    /// ditto
    public override QuorumConfig[] getExpectedQuorums (in PublicKey[], Height)
    {
        assert(0);
    }
}

/// A Validator which also implements test routines in TestAPI
public class TestValidatorNode : Validator, TestAPI
{
    ///
    mixin TestNodeMixin!();

    ///
    public this (Config config, Registry!TestAPI* reg, Registry!NameRegistryAPI* nreg,
        immutable(Block)[] blocks, in TestConf test_conf, shared(TimePoint)* cur_time)
    {
        this.registry = reg;
        this.nregistry = nreg;
        this.blocks = blocks;
        this.cur_time = cur_time;
        this.test_start_time = *cur_time;
        super(config);
    }

    /// ditto
    public override Enrollment setRecurringEnrollment (bool doIt)
    {
        this.config.validator.recurring_enrollment = doIt;
        if (this.config.validator.recurring_enrollment)
            return this.checkAndEnroll(this.ledger.getBlockHeight());

        return Enrollment.init;
    }

    /// ditto
    public override QuorumConfig getQuorumConfig ()
    {
        return this.qc;
    }

    /// Returns an instance of a TestNominator with customizable behavior
    protected override TestNominator makeNominator (
        Parameters!(Validator.makeNominator) args)
    {
        return new TestNominator(
            this.params, this.config.validator.key_pair, args,
            this.cacheDB, this.config.validator.nomination_interval,
            &this.acceptBlock, this.test_start_time);
    }

    /// Provides a unittest-adjusted clock source for the node
    protected override TestClock makeClock (ITaskManager taskman)
    {
        return new TestClock(this.taskman,
            (out long time_offset)
            {
                return this.network.getNetTimeOffset(this.qc.threshold,
                    time_offset);
            },
            this.cur_time);
    }

    /// Gets the expected quorum config for the given keys and height
    public override QuorumConfig[] getExpectedQuorums (in PublicKey[] pub_keys,
        Height height)
    {
        Hash[] utxos;
        // We add one to height as we are interested in active validators in next block
        assert(this.enroll_man.getEnrolledUTXOs(height + 1, utxos) && utxos.length > 0);
        // See `Validator.rebuildQuorumConfig`
        const rand_seed = this.ledger.getBlockHeight() == height ?
            this.ledger.getLastBlock().header.random_seed :
            this.ledger.getBlocksFrom(height).front.header.random_seed;
        QuorumConfig[] quorums;
        foreach (pub_key; pub_keys)
            quorums ~= buildQuorumConfig(pub_key, utxos,
                this.utxo_set.getUTXOFinder(), rand_seed, this.quorum_params);
        return quorums;
    }
}

/// Convenience mixin for deriving classes
public mixin template ForwardCtor ()
{
    ///
    public this (Parameters!(typeof(super).__ctor) args)
    {
        super(args);
    }
}

/// Describes a network topology for testing purpose
public enum NetworkTopology
{
    /// The nodes know about each other's IPs,
    /// and additionally outsider nodes will connect to them.
    FullyConnected,

    /// The nodes are connected in a chain: v1 <- v2 <- v3 <- v1,
    /// and additionally outsider nodes are minimally connected to them
    /// via v1 <- o1, v2 <- o2 (o = outsider node)
    MinimallyConnected,
}

/// Node / Network / Quorum configuration for use with makeTestNetwork
public struct TestConf
{
    /// Network topology to use
    NetworkTopology topology = NetworkTopology.FullyConnected;

    /// Extra blocks to generate in addition to the genesis block
    size_t extra_blocks = 0;

    /// Number of full nodes to instantiate
    size_t full_nodes = 0;

    /// Number of extra validators which are initially outside the network
    size_t outsider_validators = 0;

    /// Maximum number of quorums in the autogenerated quorum sets
    uint max_quorum_nodes = 7;

    /// Overrides the default quorum threshold
    uint quorum_threshold = 80;

    /// Quorum shuffle cycle
    uint quorum_shuffle_interval = 30;

    /// whether to set up the peers in the config
    bool configure_network = true;

    /// the delay between request retries
    Duration retry_delay = 500.msecs;

    /// minimum clients to connect to (defaults to nodes.length - 1)
    size_t min_listeners;

    /// max retries before a request is considered failed
    size_t max_retries = 10;

    /// request timeout for each node
    Duration timeout = 5.seconds;

    /// max failed requests before a node is banned
    size_t max_failed_requests = 100;

    /// max listener nodes. If set to 0, set to this.nodes - 1
    size_t max_listeners;

    /// How often blocks should be created - in seconds
    uint block_interval_sec = 600; // unit tests can set clock forward

    /// If the enrollments will be renewed or not at the end of the cycle
    bool recurring_enrollment = true;

    /// The duration between requests for retrieving the latest blocks
    /// from all other nodes
    Duration block_catchup_interval = 2.seconds;

    /// The share that Validators would get out of the transction fees
    /// Out of 100
    public ubyte validator_tx_fee_cut = 70;

    /// How frequent the payments to Validators will be
    public uint payout_period = 5;

    /// The minimum (transaction size adjusted) fee.
    /// Transaction size adjusted fee = tx fee / tx size in bytes.
    public Amount min_fee = Amount(0);

    /// The maximum number of transactions relayed in every batch.
    /// Value 0 means no limit.
    uint relay_tx_max_num = 0;

    /// Transaction relay batch is triggered in every `relay_tx_interval`.
    /// Value 0 means, the transaction will be relayed immediately.
    Duration relay_tx_interval = 0.seconds;

    /// The minimum amount of fee a transaction has to have to be relayed.
    /// The fee is adjusted by the transaction size:
    /// adjusted fee = fee / transaction size in bytes.
    Amount relay_tx_min_fee = 0;

    /// Transaction put into the relay queue will expire, and will be removed
    /// after `relay_tx_cache_exp`.
    Duration relay_tx_cache_exp = 60.minutes;
}

/*******************************************************************************

    Creates a test network with the desired topology

    This function's only usage is to create the network topology.
    The actual behavior of the nodes that are part of the network is decided
    by the `TestNetworkManager` implementation.

    Params:
        APIManager = Type of API manager to instantiate
        test_conf = the test configuration
        params = the consensus-critical constants
        eArgs = The arguments `APIManager` has which are after `TestAPIManager`'s
                constructor arguments.

    Returns:
        The set of public key added to the node

*******************************************************************************/

public APIManager makeTestNetwork (APIManager : TestAPIManager = TestAPIManager)
    (in TestConf test_conf, Parameters!(APIManager.__ctor)[Parameters!(TestAPIManager.__ctor).length .. $] eArgs,
    string file = __FILE__, int line = __LINE__)
{
    import std.digest;
    import std.range;

    // We know we're in the main thread
    // Vibe.d messes with the scheduler - reset it
    static import std.concurrency;
    std.concurrency.scheduler = null;

    const TotalNodes = GenesisValidators + test_conf.full_nodes +
        test_conf.outsider_validators;

    ConsensusConfig makeConsensusConfig ()
    {
        ConsensusConfig result = {
            validator_cycle : GenesisValidatorCycle,
            max_quorum_nodes : test_conf.max_quorum_nodes,
            quorum_threshold : test_conf.quorum_threshold,
            quorum_shuffle_interval : test_conf.quorum_shuffle_interval,
            validator_tx_fee_cut : test_conf.validator_tx_fee_cut,
            payout_period : test_conf.payout_period,
            min_fee : test_conf.min_fee,
        };

        return result;
    }

    InterfaceConfig makeInterfaceConfig (Address address)
    {
        InterfaceConfig conf =
        {
            address : address,
        };

        return conf;
    }

    NodeConfig makeNodeConfig ()
    {
        NodeConfig conf =
        {
            retry_delay : test_conf.retry_delay,
            max_retries : test_conf.max_retries,
            timeout : test_conf.timeout,
            block_interval_sec : test_conf.block_interval_sec,
            min_listeners : test_conf.min_listeners == 0
                ? (GenesisValidators + test_conf.full_nodes) - 1
                : test_conf.min_listeners,
            max_listeners : (test_conf.max_listeners == 0)
                ? TotalNodes - 1 : test_conf.max_listeners,
            block_catchup_interval : test_conf.block_catchup_interval,
            relay_tx_max_num : test_conf.relay_tx_max_num,
            relay_tx_interval : test_conf.relay_tx_interval,
            relay_tx_min_fee : test_conf.relay_tx_min_fee,
            relay_tx_cache_exp : test_conf.relay_tx_cache_exp,
        };

        return conf;
    }

    BanManager.Config ban_conf =
    {
        max_failed_requests : test_conf.max_failed_requests,
        ban_duration: 300.seconds,
    };

    immutable(Address[]) makeNetworkConfig (size_t idx, Address[] addresses)
    {
        if (!test_conf.configure_network)
            return null;

        assert(addresses.length > 0);
        idx %= addresses.length;  // clamp to limit

        // nodes form a network chain: n2 <- n0 <- n1 <- n2
        if (test_conf.topology == NetworkTopology.MinimallyConnected)
            return [(idx == 0) ? addresses[$ - 1] : addresses[idx - 1]]
                .assumeUnique;
        else
            return addresses.idup;
    }

    Config makeValidatorConfig (size_t idx, KeyPair key_pair,
        Address self_address, Address[] addresses)
    {
        const ValidatorConfig validator = {
            enabled : true,
            key_pair : key_pair,
            addresses_to_register : [self_address],
            registry_address : "name.registry",
            recurring_enrollment : test_conf.recurring_enrollment,
            preimage_reveal_interval : 1.seconds,  // check revealing frequently
            nomination_interval: 100.msecs,
        };

        Config conf =
        {
            banman : ban_conf,
            node : makeNodeConfig(),
            interfaces: [ makeInterfaceConfig(self_address) ],
            consensus: makeConsensusConfig(),
            validator : validator,
            network : makeNetworkConfig(idx, addresses),
        };

        return conf;
    }

    Config makeFullNodeConfig (size_t idx, Address self_address,
        Address[] addresses)
    {
        Config conf =
        {
            banman : ban_conf,
            node : makeNodeConfig(),
            interfaces: [ makeInterfaceConfig(self_address) ],
            consensus: makeConsensusConfig(),
            network : makeNetworkConfig(idx, addresses),
        };

        return conf;
    }

    string validatorAddress (size_t idx, KeyPair key)
    {
        return format("Validator #%s (%s)", idx, key.address);
    }

    string fullNodeAddress (size_t idx)
    {
        return format("FullNode #%s", idx);
    }

    auto outsider_validators_keys = WK.Keys.byRange()
        .takeExactly(test_conf.outsider_validators);

    auto validator_keys = genesis_validator_keys ~ outsider_validators_keys.array;

    // all enrolled and un-enrolled validators
    auto validator_addresses = validator_keys.enumerate
        .map!(en => validatorAddress(en.index, en.value)).array;

    // only enrolled validators
    auto enrolled_addresses = genesis_validator_keys.enumerate
        .takeExactly(GenesisValidators)
        .map!(en => validatorAddress(en.index, en.value)).array;

    auto full_node_addresses = test_conf.full_nodes.iota.map!(
        idx => fullNodeAddress(idx)).array;

    // full nodes and enrolled validators will connect to other enrolled validators
    // and other full nodes (but not to outsider nodes)
    auto connect_addresses = enrolled_addresses.chain(full_node_addresses);

    auto validator_configs = validator_keys.enumerate
        .map!(en => makeValidatorConfig(
            en.index,
            en.value,
            validator_addresses[en.index],
            connect_addresses.filter!(  // don't connect the validator to itself
                addr => addr != validator_addresses[en.index]).array));

    auto full_node_configs = test_conf.full_nodes
        .iota
        .map!(index => makeFullNodeConfig(
            index + enrolled_addresses.length,
            full_node_addresses[index],
            connect_addresses.filter!(  // don't connect the fullnode to itself
                addr => addr != full_node_addresses[index]).array));

    auto all_configs = validator_configs.chain(full_node_configs).array;

    foreach (ref conf; all_configs)
        conf.node.testing = true;

    immutable(Block)[] blocks = generateExtraBlocks(GenesisBlock,
        test_conf.extra_blocks);

    auto net = new APIManager(blocks, test_conf, validator_configs[0].consensus.genesis_timestamp, eArgs);
    foreach (ref conf; all_configs)
        net.createNewNode(conf, file, line);

    return net;
}


/// Returns: the entire ledger from the provided node
public const(Block)[] getAllBlocks (TestAPI node)
{
    import std.range;
    const(Block)[] blocks;

    // note: may return less than asked for, hence the loop
    size_t starting_block = 0;
    while (1)
    {
        auto new_blocks = node.getBlocksFrom(starting_block, uint.max);
        if (new_blocks.length == 0)  // no blocks left
            break;

        // ensure sequential consistency
        foreach (block; new_blocks)
            assert(block.header.height == starting_block++);

        blocks ~= new_blocks;
    }

    return blocks;
}

/*******************************************************************************

    Generate a set of blocks with spend transactions

    Params:
        gen_block = the genesis block
        count = the number of extra blocks to generate. If 0, the return
                blockchain will only contain the genesis block.

    Returns:
        The blockchain, including the provided genesis block

*******************************************************************************/

private immutable(Block)[] generateExtraBlocks (
    ref immutable Block gen_block, size_t count)
{
    const(Block)[] blocks = [gen_block];
    if (count == 0)
        return blocks.assumeUnique;  // just the genesis block

    foreach (_; 0 .. count)
    {
        auto txs = blocks[$ - 1].spendable().map!(txb => txb.sign());
        const block = makeNewTestBlock(blocks[$ - 1], txs);
        blocks ~= block;
    }
    return blocks.assumeUnique;
}
