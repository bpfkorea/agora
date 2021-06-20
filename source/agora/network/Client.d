/*******************************************************************************

    Contains code used to communicate with another remote node

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.network.Client;

import agora.api.Validator;
import agora.common.BanManager;
import agora.common.Set;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.data.Enrollment;
import agora.consensus.data.PreImageInfo;
import agora.consensus.data.Transaction;
import agora.consensus.data.ValidatorBlockSig;
import agora.crypto.Key;
import scpd.types.Stellar_SCP;

import agora.utils.Log;

import vibe.http.client;

import std.algorithm;
import std.array;
import std.container : DList;
import std.format;
import std.random;

import core.time;

/// Used for communicating with a remote node
public class NetworkClient
{
    /// Gossip type
    enum GossipType
    {
        Tx,
        Envelope,
        ValidatorBlockSig,
        Enrollment,
        Preimage,
    }

    /// Outgoing gossip event
    static struct GossipEvent
    {
        /// Union flag
        GossipType type;

        union
        {
            Transaction tx;
            SCPEnvelope envelope;
            ValidatorBlockSig block_sig;
            Enrollment enrollment;
            PreImageInfo preimage;
        }

        this (Transaction tx) nothrow
        {
            this.type = GossipType.Tx;
            this.tx = tx;
        }

        this (SCPEnvelope envelope) nothrow
        {
            this.type = GossipType.Envelope;
            this.envelope = envelope;
        }

        this (ValidatorBlockSig sig) nothrow
        {
            this.type = GossipType.ValidatorBlockSig;
            this.block_sig = sig;
        }

        this (Enrollment enr) nothrow
        {
            this.type = GossipType.Enrollment;
            this.enrollment = enr;
        }

        this (PreImageInfo preimage) nothrow
        {
            this.type = GossipType.Preimage;
            this.preimage = preimage;
        }
    }

    /// Whether to throw an exception when attemptRequest() fails
    protected enum Throw
    {
        ///
        No,

        ///
        Yes
    }

    /// Address of the node we're interacting with (for logging)
    public const Address address;

    /// Caller's retry delay
    /// TODO: This should be done at the client object level,
    /// so whatever implements `API` should be handling this
    private const Duration retry_delay;

    /// Max request retries before a request is considered failed
    private const size_t max_retries;

    /// Task manager
    private ITaskManager taskman;

    /// Ban manager
    private BanManager banman;

    /// API client to the node
    protected API api;

    /// Reusable exception
    private Exception exception;

    /// List of outgoing gossip events
    private DList!GossipEvent gossip_queue;

    /// Timer used for gossiping
    private ITimer gossip_timer;

    /// Logger uniquely identifying this client
    private Logger log;

    /***************************************************************************

        Constructor.

        Params:
            taskman = used for creating new tasks
            banman = ban manager
            address = used for logging and querying by external code
            api = the API to issue the requests with
            retry = the amout to wait between retrying failed requests
            max_retries = max number of times a failed request should be retried

    ***************************************************************************/

    public this (ITaskManager taskman, BanManager banman, Address address,
        API api, Duration retry, size_t max_retries)
    {
        // By default, use the module, but if we can identify a validator,
        // this logger will be replaced with a more specialized one.
        this.log = Log.lookup(__MODULE__);
        this.taskman = taskman;
        this.banman = banman;
        this.address = address;
        this.api = api;
        this.retry_delay = retry;
        this.max_retries = max_retries;
        this.exception = new Exception(
            format("Request failure to %s after %s attempts", address,
                max_retries));
        this.gossip_timer = this.taskman.setTimer(10.msecs, &this.gossipTask, Periodic.Yes);
    }

    /// Shut down the gossiping timer
    public void shutdown () @safe
    {
        this.gossip_timer.stop();
    }

    /// For gossiping we don't want to block the calling fiber, so we use
    /// request queueing and a separate fiber to handle all the outgoing requests.
    private void gossipTask ()
    {
        while (!this.gossip_queue.empty)
        {
            auto event = this.gossip_queue.front;
            this.gossip_queue.removeFront();
            this.handleGossip(event);
            // yield and reschedule for next event
        }
    }

    /// Handle an outgoing gossip event
    private void handleGossip (GossipEvent event) nothrow
    {
        switch (event.type) with (GossipType)
        {
        case Tx:
            this.attemptRequest!(API.putTransaction, Throw.No)(this.api,
                event.tx);
            break;

        case Envelope:
            this.attemptRequest!(API.receiveEnvelope, Throw.No)(this.api,
                event.envelope);
            break;

        case ValidatorBlockSig:
            this.attemptRequest!(API.receiveBlockSignature, Throw.No)(this.api,
                event.block_sig);
            break;

        case Enrollment:
            this.attemptRequest!(API.enrollValidator, Throw.No)(this.api,
                event.enrollment);
            break;

        case Preimage:
            this.attemptRequest!(API.receivePreimage, Throw.No)(this.api,
                event.preimage);
            break;

        default:
            assert(0);
        }
    }

    /***************************************************************************

        Change this client's logger to make it easier to identify peers and
        selectively enable or disable logging

        Params:
          key = Public key of this peer

    ***************************************************************************/

    public void setIdentity (in PublicKey key)
    {
        this.log = Log.lookup(format("%s.%s", __MODULE__, key));
        this.log.info("Peer identity established");
    }

    /***************************************************************************

        Params:
            key = key of the peer

        Returns:
            The public key of this node and a secret to prove identity

        Throws:
            `Exception` if the request failed.

    ***************************************************************************/

    public Identity getPublicKey (PublicKey key = PublicKey.init) @trusted
    {
        return this.attemptRequest!(API.getPublicKey, Throw.Yes)(this.api,
            key);
    }

    /***************************************************************************

        Get the network info of the node, stored in the
        `node_info` parameter if the request succeeded.

        Returns:
            `NodeInfo` if successful

        Throws:
            `Exception` if the request failed.

    ***************************************************************************/

    public NodeInfo getNodeInfo ()
    {
        return this.attemptRequest!(API.getNodeInfo, Throw.Yes)(this.api);
    }

    /***************************************************************************

        Get the local time of the node

        Returns:
            the local time of the node, or 0 if the request failed

    ***************************************************************************/

    public TimePoint getLocalTime () @trusted nothrow
    {
        return this.attemptRequest!(API.getLocalTime, Throw.No)(this.api);
    }

    /***************************************************************************

        Send a transaction asynchronously to the node.
        Any errors are reported to the debugging log.

        The request is retried up to 'this.max_retries',
        any failures are logged and ignored.

        Params:
            tx = the transaction to send

    ***************************************************************************/

    public void sendTransaction (Transaction tx) @trusted nothrow
    {
        this.gossip_queue.insertBack(GossipEvent(tx));
    }


    /***************************************************************************

        Sends an SCP envelope to another node.

        Params:
            envelope = the envelope to send

    ***************************************************************************/

    public void sendEnvelope (SCPEnvelope envelope) nothrow
    {
        this.gossip_queue.insertBack(GossipEvent(envelope));
    }

    /***************************************************************************

        Sends a Validator Block Signature to the node.

        Params:
            block_sig = the details of the block signature

    ***************************************************************************/

    public void sendBlockSignature (ValidatorBlockSig block_sig) nothrow
    {
        this.gossip_queue.insertBack(GossipEvent(block_sig));
    }

    /***************************************************************************

        Returns:
            the height of the node's ledger,
            or ulong.max if the request failed

        Throws:
            Exception if the request failed.

    ***************************************************************************/

    public ulong getBlockHeight ()
    {
        return this.attemptRequest!(API.getBlockHeight, Throw.Yes)(this.api);
    }

    /***************************************************************************

        Get the array of blocks starting from the provided block height.
        The block at height is included in the array.

        Params:
            height = the starting block height to begin retrieval from
            max_blocks   = the maximum blocks to return at once

        Returns:
            the array of blocks starting from height,
            up to `max_blocks`.

            If the request failed, returns an empty array

    ***************************************************************************/

    public const(Block)[] getBlocksFrom (ulong height, uint max_blocks)
        nothrow
    {
        return this.attemptRequest!(API.getBlocksFrom, Throw.No)(this.api,
            height, max_blocks);
    }

    /***************************************************************************

        Send a enrollment request asynchronously to the node.
        Any errors are reported to the debugging log.

        The request is retried up to 'this.max_retries',
        any failures are logged and ignored.

        Params:
            enroll = the enrollment data to send

    ***************************************************************************/

    public void sendEnrollment (Enrollment enroll) @trusted nothrow
    {
        this.gossip_queue.insertBack(GossipEvent(enroll));
    }

    /***************************************************************************

        Send a preimage asynchronously to the node.
        Any errors are reported to the debugging log.

        The request is retried up to 'this.max_retries',
        any failures are logged and ignored.

        Params:
            preimage = the pre-image information to send

    ***************************************************************************/

    public void sendPreimage (PreImageInfo preimage) @trusted nothrow
    {
        this.gossip_queue.insertBack(GossipEvent(preimage));
    }

    /***************************************************************************

        Params:
            tx_hashes = A Set of Transaction hashes

        Returns:
            Transactions corresponding to the requested hashes or
            Transaction.init for hashes that can't be found in the pool

    ***************************************************************************/

    public Transaction[] getTransactions (Set!Hash tx_hashes) @trusted nothrow
    {
        return this.attemptRequest!(API.getTransactions, Throw.No)(this.api,
            tx_hashes);
    }

    /***************************************************************************

        Params:
            heights = Set of block heights

        Returns:
            Block headers for the requested block heights

    ***************************************************************************/

    public BlockHeader[] getBlockHeaders (Set!ulong heights) @trusted nothrow
    {
        return this.attemptRequest!(API.getBlockHeaders, Throw.No)(this.api,
            heights);
    }

    /***************************************************************************

        Get the array of pre-images starting from the `enrolled_height`.

        Params:
            start_height = the starting enrolled height to begin retrieval from
            end_height = the end enrolled height to finish retrieval to

        Returns:
            the array of preimages of validators enrolling from `enrolled_height`
            to `end_height`

            If the request failed, returns an empty array

    ***************************************************************************/

    public PreImageInfo[] getPreimages (ulong start_height,
        ulong end_height) nothrow
    {
        return this.attemptRequest!(API.getPreimages, Throw.No)(this.api,
            start_height, end_height);
    }

    /***************************************************************************

        Attempt a request up to 'this.max_retries' attempts, and make the task
        wait this.retry_delay between each attempt.

        If all requests fail and 'ex' is not null, throw the exception.

        Params:
            endpoint = the API endpoint (e.g. `API.putTransaction`)
            DT = whether to throw an exception if the request failed after
                 all attempted retries
            log_level = the logging level to use for logging failed requests
            API = deduced
            Args = deduced
            api = the interface to communicate with a node
            args = the arguments to the API endpoint

        Returns:
            the return value of of the API call, which may be void

    ***************************************************************************/

    protected auto attemptRequest (alias endpoint, Throw DT,
        LogLevel log_level = LogLevel.Trace, API, Args...)
        (API api, auto ref Args args, string file = __FILE__, uint line = __LINE__)
    {
        import std.traits;
        enum name = __traits(identifier, endpoint);
        alias T = ReturnType!(__traits(getMember, api, name));

        foreach (idx; 0 .. this.max_retries)
        {
            try
            {
                return __traits(getMember, api, name)(args);
            }
            catch (Exception ex)
            {
                import vibe.http.common : HTTPStatusException;
                if (auto http = cast(HTTPStatusException)ex)
                {
                    static if (DT == Throw.Yes)
                        throw http;  // e.g. getPublicKey() might not be implemented
                    else
                        break;
                }

                try
                {
                    this.log.format(log_level, "Request '{}' to {} failed: {}",
                        name, this.address, ex.message);
                }
                catch (Exception ex)
                {
                    // nothing we can do
                }

                if (idx + 1 < this.max_retries) // wait after each failure except last
                    this.taskman.wait(this.retry_delay);
            }
        }

        // request considered failed after max retries reached
        this.banman.onFailedRequest(this.address);

        static if (DT == Throw.Yes)
        {
            this.exception.file = file;
            this.exception.line = line;
            throw this.exception;
        }
        else static if (!is(T == void))
            return T.init;
    }
}
