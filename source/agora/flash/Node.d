/*******************************************************************************

    Contains the Flash abstract node definition.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.Node;

import agora.api.FullNode : FullNodeAPI = API;
import agora.common.Amount;
import agora.common.ManagedDatabase;
import agora.common.Set;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.data.Transaction;
import agora.consensus.data.UTXO;
import agora.crypto.ECC;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.crypto.Schnorr;
import agora.flash.api.FlashAPI;
import agora.flash.Channel;
import agora.flash.Config;
import agora.flash.api.FlashControlAPI;
import agora.flash.api.FlashListenerAPI;
import agora.flash.ErrorCode;
import agora.flash.Invoice;
import agora.flash.Network;
import agora.flash.OnionPacket;
import agora.flash.Route;
import agora.flash.Scripts;
import agora.flash.Types;
import agora.network.Manager;
import agora.script.Engine;
import agora.registry.API;
import agora.serialization.Serializer;
import agora.utils.InetUtils;
import agora.utils.Log;

import vibe.http.router;
import vibe.http.server;
import vibe.web.rest;

import core.stdc.time;
import core.time;

import std.algorithm;
import std.container : DList;
import std.conv;
import std.format;
import std.range;
import std.path;
import std.stdio;
import std.traits;
import std.typecons;

/// Gossip type
private enum GossipType
{
    Open,
    Update,
}

/// Outgoing gossip event
private struct GossipEvent
{
    /// Union flag
    GossipType type;

    union
    {
        ChannelConfig open;
        ChannelUpdate update;
    }

    this (ChannelConfig open) @trusted nothrow
    {
        this.type = GossipType.Open;
        this.open = open;
    }

    this (ChannelUpdate update) @trusted nothrow
    {
        this.type = GossipType.Update;
        this.update = update;
    }
}

/// Ditto
public abstract class FlashNode : FlashControlAPI
{
    /// Logger instance
    protected Logger log;

    /// Flash config which remains static after boot but may change after restart
    protected FlashConfig conf;

    /// Hash of the genesis block
    protected const Hash genesis_hash;

    /// All the node metadata
    mixin NodeMetadata!() meta;

    /// Serialization buffer
    private ubyte[] serialize_buffer;

    /// Execution engine
    protected Engine engine;

    /// for scheduling
    protected ITaskManager taskman;

    /// List of outgoing gossip events
    private DList!GossipEvent gossip_queue;

    /// Timer used for gossiping
    private ITimer gossip_timer;

    /// Timer used for opening new channels
    private ITimer open_chan_timer;

    /// Flash network topology
    protected Network network;

    /// List of channels which are pending to be opened
    protected DList!ChannelConfig[PublicKey] pending_channels;

    /// All channels which we are the participants of (open / pending / closed)
    protected Channel[Hash][PublicKey] channels;

    /// All known connected peers (used for gossiping)
    protected FlashAPI[PublicKey] known_peers;

    /// Any listener
    protected FlashListenerAPI listener;

    /// Metadata database
    private ManagedDatabase db;

    /***************************************************************************

        Constructor

        Params:
            conf = the configuration of this node
            db_path = path to the database (or in-memory if set to ":memory:")
            genesis_hash = the hash of the genesis block to use
            engine = the execution engine to use
            taskman = the task manager ot use

        Returns:
            the Agora FullNode client

    ***************************************************************************/

    public this (FlashConfig conf, string db_path, Hash genesis_hash,
        Engine engine, ITaskManager taskman)
    {
        this.conf = conf;
        this.genesis_hash = genesis_hash;
        this.engine = engine;
        // todo: use this in the logger call instead of the logger name
        // this.conf.key_pair.address.flashPrettify()
        this.log = Logger(__MODULE__);
        this.taskman = taskman;
        this.db = this.getManagedDatabase(db_path);
        this.load();

        this.channels = Channel.loadChannels(this.conf, this.db,
            &this.getFlashClient, engine, taskman,
            &this.putTransaction, &this.paymentRouter,
            &this.onChannelNotify,
            &this.onPaymentComplete, &this.onUpdateComplete);

        this.network = new Network((Hash chan_id, Point from) {
            if (auto updates = chan_id in this.channel_updates)
            {
                auto config = this.known_channels[chan_id];
                auto dir = from == config.funder_pk ? PaymentDirection.TowardsPeer :
                    PaymentDirection.TowardsOwner;
                if (auto dir_update = dir in *updates)
                    return *dir_update;
            }
            return ChannelUpdate.init;
        });

        // todo: filter out adding the same channel twice (both parties)
        foreach (point, chans; this.channels)
            foreach (_, chan; chans)
                this.network.addChannel(chan.conf);
    }

    /***************************************************************************

        Start the gossiping timer and connect to the listener

    ***************************************************************************/

    public override void start () @trusted
    {
        if (this.conf.listener_address.length != 0)
            this.listener = this.getFlashListenerClient(
                this.conf.listener_address, this.conf.timeout);
        else  // avoid null checks & segfaults
            this.listener = new BlackHole!FlashListenerAPI();

        this.gossip_timer = this.taskman.setTimer(100.msecs,
            &this.gossipTask, Periodic.Yes);
        this.open_chan_timer = this.taskman.setTimer(100.msecs,
            &this.channelOpenTask, Periodic.Yes);
    }

    /***************************************************************************

        Returns:
            a key/value range of the managed key-pairs

    ***************************************************************************/

    public auto getManagedKeys ()
    {
        return this.managed_keys.byKeyValue();
    }

    /***************************************************************************

        Register the given key-pair to be used with this Flash node.

    ***************************************************************************/

    public override void registerKey (Scalar scalar) @safe
    {
        auto secret = SecretKey(scalar);
        auto address = PublicKey(scalar.toPoint()[]);
        this.managed_keys[address] = secret;
        this.channels[address] = typeof(this.channels[address]).init;
        this.pending_channels[address] = typeof(this.pending_channels[address]).init;
    }

    /***************************************************************************

        Get the list of managed channels.

        Params:
            keys = the keys to look up. If empty, all managed channels will
                be returned.

        Returns:
            the list of all managed channels by this Flash node for the
            given public keys (if any)

    ***************************************************************************/

    public override ChannelConfig[] getManagedChannels (PublicKey[] keys) @safe
    {
        auto filtered = sort(this.channels.byKey
            .filter!(k => !keys.length || keys.canFind(k)).array);
        return filtered.map!(key =>
            this.channels[key].byValue.map!(chan => chan.conf)).joiner().array;
    }

    /***************************************************************************

        Get the list of managed channels.

        Params:
            chan_ids = the channel keys to look up. If empty then all managed
                channel info will be returned.

        Returns:
            the list of all managed channels by this Flash node for the
            given public keys (if any)

    ***************************************************************************/

    public override ChannelInfo[] getChannelInfo (Hash[] chan_ids) @safe
    {
        ChannelInfo[] all;
        foreach (_, chans; this.channels)
        foreach (id, chan; chans)
        {
            if (!chan_ids.empty && !chan_ids.canFind(id))
                continue;  // not found

            ChannelInfo info =
            {
                chan_id : chan.conf.chan_id,
                owner_key : chan.conf.funder_pk,
                peer_key : chan.conf.peer_pk,
                // note: terminology is confusing, this is the available balance
                // towards the peer and therefore the owner's balance.
                owner_balance : chan.getBalance(PaymentDirection.TowardsPeer),
                peer_balance : chan.getBalance(PaymentDirection.TowardsOwner),
                state : chan.getState()
            };

            all ~= info;
        }

        return all;
    }

    /***************************************************************************

        Store all the node's and each channels' metadata to the DB,
        and shut down the gossiping timer.

    ***************************************************************************/

    public void shutdown () @safe
    {
        this.gossip_timer.stop();
        this.open_chan_timer.stop();

        try this.dump();
        catch (Exception exc)
        {
            () @trusted {
                printf("Error happened while dumping this node's state: %.*s\n",
                       cast(int) exc.msg.length, exc.msg.ptr);

                scope (failure) assert(0);
                writeln("========================================");
                writeln("Full stack trace: ", exc);
            }();
        }

        foreach (pair; this.channels.byKeyValue)
        {
            foreach (chan; pair.value)
            {
                try chan.dump();
                catch (Exception exc)
                {
                    scope (failure) assert(0);
                    () @trusted {
                        writefln("Error happened while dumping a channel's (%s) state: %s",
                                 pair.key, exc);
                    }();
                }
            }
        }
    }

    /***************************************************************************

        Gossiping fiber routine.

    ***************************************************************************/

    private void gossipTask ()
    {
        while (!this.gossip_queue.empty)
        {
            auto event = this.gossip_queue.front;
            this.gossip_queue.removeFront();
            this.handleGossip(event);
            this.taskman.wait(1.msecs);  // yield
        }
    }

    /***************************************************************************

        Fiber routine dedicated to opening channels.

    ***************************************************************************/

    private void channelOpenTask ()
    {
        foreach (reg_pk, ref pending; this.pending_channels)
        {
            while (!pending.empty)
            {
                auto chan_conf = pending.front;
                scope (exit) pending.removeFront();
                this.handleOpenNewChannel(PublicKey(reg_pk), chan_conf);
                this.taskman.wait(1.msecs);  // yield
            }
        }
    }

    /// Handle an outgoing gossip event
    private void handleGossip (GossipEvent event)
    {
        foreach (peer; this.known_peers.byKeyValue)
        final switch (event.type) with (GossipType)
        {
        case Open:
            peer.value.gossipChannelsOpen([event.open].staticArray);
            break;
        case Update:
            peer.value.gossipChannelUpdates([event.update].staticArray);
            break;
        }
    }

    /***************************************************************************

        Change the fees for the given channel ID.

        Params:
            key = the registered public key
            chan_id = the channel ID to change the fees for
            fixed_fee = the new fixed fee
            proportional_fee = the new proportional fee

    ***************************************************************************/

    public override void changeFees (PublicKey key, Hash chan_id,
        Amount fixed_fee, Amount proportional_fee)
    {
        this.gossipChannelUpdates(
            [this.channels[key][chan_id].updateFees(fixed_fee, proportional_fee)]);
    }

    /***************************************************************************

        Overridable in tests to test restart behavior.

        Params:
            db_path = path to the database

        Returns:
            a ManagedDatabase instance for the given path

    ***************************************************************************/

    protected ManagedDatabase getManagedDatabase (string db_path)
    {
        return new ManagedDatabase(db_path);
    }

    /***************************************************************************

        Serialize and dump the node metadata to the database.

    ***************************************************************************/

    private void dump () @trusted
    {
        this.serialize_buffer.length = 0;
        () @trusted { assumeSafeAppend(this.serialize_buffer); }();
        scope SerializeDg dg = (in ubyte[] data) @safe
        {
            this.serialize_buffer ~= data;
        };

        foreach (name; __traits(allMembers, this.meta))
        {
            auto field = __traits(getMember, this.meta, name);
            static if (isAssociativeArray!(typeof(field)))
                serializePart(serializeMap(field), dg);
            else
                serializePart(field, dg);
        }

        this.db.execute("REPLACE INTO flash_metadata (meta, data) VALUES (1, ?)",
            this.serialize_buffer);
    }

    /***************************************************************************

        Load any node metadata from the database.

    ***************************************************************************/

    private void load () @trusted
    {
        db.execute("CREATE TABLE IF NOT EXISTS flash_metadata " ~
            "(meta BLOB NOT NULL PRIMARY KEY, data BLOB NOT NULL)");

        auto results = this.db.execute(
            "SELECT data FROM flash_metadata WHERE meta = 1");
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
            else
                *field = deserializeFull!Type(dg);
        }
    }

    /***************************************************************************

        Get an instance of a Flash client for the given public key.

        Params:
            peer_pk = the public key of the Flash node.
            timeout = the timeout duration to use for requests.

        Returns:
            the Flash client

    ***************************************************************************/

    protected abstract FlashAPI getFlashClient (in PublicKey peer_pk,
        Duration timeout) @trusted;

    /***************************************************************************

        Get an instance of a FlashListenerAPI client for the given address.

        Params:
            peer_pk = the public key of the Flash node.
            timeout = the timeout duration to use for requests.

        Returns:
            the FlashListenerAPI client

    ***************************************************************************/

    protected abstract FlashListenerAPI getFlashListenerClient (string address,
        Duration timeout) @trusted;

    /// See `FlashAPI.openChannel`
    public override Result!PublicNonce openChannel (
        PublicKey recv_pk, /*in*/ ChannelConfig chan_conf,
        /*in*/ PublicNonce peer_nonce) @trusted
    {
        // todo: verify `chan_conf.funding_utxo`
        log.info("openChannel()");

        auto secret_key = recv_pk in this.managed_keys;
        if (secret_key is null)
            return Result!PublicNonce(ErrorCode.KeyNotRecognized,
                format("The provided key %s is not managed by this "
                ~ "Flash node. Do you have the right address..?", recv_pk));

        if (auto chans = recv_pk in this.channels)
            if (chan_conf.chan_id in *chans)
                return Result!PublicNonce(ErrorCode.DuplicateChannelID,
                    "There is already an open channel with this ID");

        auto peer = this.getFlashClient(chan_conf.funder_pk, this.conf.timeout);
        if (peer is null)
            return Result!PublicNonce(ErrorCode.AddressNotFound,
                format("Cannot find address of flash node in registry for the key %s",
                    chan_conf.funder_pk));

        if (chan_conf.gen_hash != this.genesis_hash)
            return Result!PublicNonce(ErrorCode.InvalidGenesisHash,
                "Unrecognized blockchain genesis hash");

        if (chan_conf.capacity < this.conf.min_funding ||
            chan_conf.capacity > this.conf.max_funding)
            return Result!PublicNonce(ErrorCode.RejectedFundingAmount,
                format("Funding amount rejected. Want between %s and %s",
                    this.conf.min_funding, this.conf.max_funding));

        if (chan_conf.settle_time < this.conf.min_settle_time ||
            chan_conf.settle_time > this.conf.max_settle_time)
            return Result!PublicNonce(ErrorCode.RejectedSettleTime, format(
                "Settle time rejecteds. Want between %s and %s",
                this.conf.min_settle_time, this.conf.max_settle_time));

        if (auto error = this.listener.onRequestedChannelOpen(recv_pk,
            chan_conf))
            return Result!PublicNonce(ErrorCode.UserRejectedChannel, error);

        PrivateNonce priv_nonce = genPrivateNonce();
        const key_pair = KeyPair.fromSeed(*secret_key);
        auto channel = new Channel(this.conf, chan_conf, key_pair,
            priv_nonce, peer_nonce, peer, this.engine, this.taskman,
            &this.putTransaction, &this.paymentRouter, &this.onChannelNotify,
            &this.onPaymentComplete, &this.onUpdateComplete, this.db);

        this.channels[recv_pk][chan_conf.chan_id] = channel;
        this.network.addChannel(chan_conf);
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();
        return Result!PublicNonce(pub_nonce);
    }

    /// Overriden by ThinFlashNode or FullNode
    protected abstract void putTransaction (Transaction tx);

    /// See `FlashAPI.closeChannel`
    public override Result!Point closeChannel (PublicKey sender_pk,
        PublicKey recv_pk, /* in */ Hash chan_id, /* in */ uint seq_id,
        /* in */ Point peer_nonce, /* in */ Amount fee ) @trusted
    {
        if (auto chans = recv_pk in this.channels)
            if (auto channel = chan_id in *chans)
                return channel.requestCloseChannel(seq_id, peer_nonce, fee);

        return Result!Point(ErrorCode.InvalidChannelID,
            "Channel ID not found");
    }

    protected void onChannelNotify (PublicKey reg_pk, Hash chan_id,
        ChannelState state, ErrorCode error) @safe
    {
        // gossip to the network
        if (state == ChannelState.Open)  // todo: might not exist
            this.onChannelOpen(reg_pk, this.channels[reg_pk][chan_id].conf);

        this.listener.onChannelNotify(reg_pk, chan_id, state, error);
    }

    ///
    private void onChannelOpen (PublicKey reg_pk, ChannelConfig conf) @safe
    {
        log.info("onChannelOpen() with channel {}", conf.chan_id);

        this.known_channels[conf.chan_id] = conf;
        this.network.addChannel(conf);

        const dir = reg_pk == conf.funder_pk ?
            PaymentDirection.TowardsPeer : PaymentDirection.TowardsOwner;
        // Set the initial fees
        // todo: this should be configurable
        // todo: can throw if channel is missing
        auto update = this.channels[reg_pk][conf.chan_id].getChannelUpdate();
        this.channel_updates[conf.chan_id][dir] = update;

        // todo: should not gossip this to counterparty of the just opened channel
        this.gossip_queue.insertBack(GossipEvent(conf));
        this.gossip_queue.insertBack(GossipEvent(update));

        this.dump();
    }

    /// See `FlashAPI.gossipChannelsOpen`
    public override void gossipChannelsOpen ( ChannelConfig[] chan_configs )
    {
        log.info("gossipChannelsOpen() with {} channels", chan_configs.length);

        foreach (conf; chan_configs)
        {
            if (conf.chan_id in this.known_channels)
                continue;

            log.info("gossipChannelsOpen(): Discovered: {}",
                     conf.chan_id.flashPrettify);

            // todo: need to verify the blockchain actually contains the
            // funding transaction, otherwise this becomes a point of DDoS.
            this.known_channels[conf.chan_id] = conf;
            this.network.addChannel(conf);

            this.gossip_queue.insertBack(GossipEvent(conf));  // gossip only new channels
        }
    }

    /// See `FlashAPI.gossipChannelUpdates`
    public void gossipChannelUpdates (ChannelUpdate[] chan_updates)
    {
        log.info("gossipChannelUpdates() with {} channels", chan_updates);

        foreach (update; chan_updates)
        {
            if (auto conf = update.chan_id in this.known_channels)
            {
                auto pk = update.direction == PaymentDirection.TowardsPeer ?
                                                conf.funder_pk : conf.peer_pk;
                if (auto chan_update = update.chan_id in this.channel_updates)
                    if (auto dir_update = update.direction in *chan_update)
                    {
                        if (*dir_update == update // same fees as before
                            || update.update_idx <= dir_update.update_idx)  // must be newer (replay attacks)
                            continue;
                    }

                if (!verify(pk, update.sig, update))
                {
                    log.info("gossipChannelUpdates() rejected bad signature: {}",
                        update);
                    continue;
                }
                this.channel_updates[update.chan_id][update.direction] = update;
                log.info("gossipChannelUpdates() added channel update: {}. chan_id: {}. direction: {}. address: {}",
                        update, update.chan_id, update.direction, cast(void*)&this.channel_updates);
                this.gossip_queue.insertBack(GossipEvent(update));
                this.dump();
            }
            else
            {
                log.info("gossipChannelUpdates() rejected missing channel update: {}",
                    update);
            }
        }
    }

    /// See `FlashAPI.requestCloseSig`
    public override Result!Signature requestCloseSig (PublicKey sender_pk,
        PublicKey recv_pk, /* in */ Hash chan_id, /* in */ uint seq_id) @trusted
    {
        auto secret_key = recv_pk in this.managed_keys;
        if (secret_key is null)
            return Result!Signature(ErrorCode.KeyNotRecognized,
                format("The provided key %s is not managed by this "
                ~ "Flash node. Do you have the right address..?", recv_pk));

        if (auto chans = recv_pk in this.channels)
        if (auto channel = chan_id in *chans)
        {
            if (sender_pk != channel.peer_pk)
                return Result!Signature(ErrorCode.KeyNotRecognized,
                    format("Sender key does not belong to this channel: {}",
                        sender_pk));

            return channel.requestCloseSig(seq_id);
        }

        return Result!Signature(ErrorCode.InvalidChannelID,
            "Channel ID not found");
    }

    /// See `FlashAPI.requestSettleSig`
    public override Result!Signature requestSettleSig (PublicKey sender_pk,
        PublicKey recv_pk, /* in */ Hash chan_id, /* in */ uint seq_id) @trusted
    {
        auto secret_key = recv_pk in this.managed_keys;
        if (secret_key is null)
            return Result!Signature(ErrorCode.KeyNotRecognized,
                format("The provided key %s is not managed by this "
                ~ "Flash node. Do you have the right address..?", recv_pk));

        if (auto chans = recv_pk in this.channels)
        if (auto channel = chan_id in *chans)
        {
            if (sender_pk != channel.peer_pk)
                return Result!Signature(ErrorCode.KeyNotRecognized,
                    format("Sender key does not belong to this channel: {}",
                        sender_pk));

            return channel.onRequestSettleSig(seq_id);
        }

        return Result!Signature(ErrorCode.InvalidChannelID,
            "Channel ID not found");
    }

    /// See `FlashAPI.requestUpdateSig`
    public override Result!Signature requestUpdateSig (PublicKey sender_pk,
        PublicKey recv_pk, /* in */ Hash chan_id, /* in */ uint seq_id) @trusted
    {
        auto secret_key = recv_pk in this.managed_keys;
        if (secret_key is null)
            return Result!Signature(ErrorCode.KeyNotRecognized,
                format("The provided key %s is not managed by this "
                ~ "Flash node. Do you have the right address..?", recv_pk));

        if (auto chans = recv_pk in this.channels)
        if (auto channel = chan_id in *chans)
        {
            if (sender_pk != channel.peer_pk)
                return Result!Signature(ErrorCode.KeyNotRecognized,
                    format("Sender key does not belong to this channel: {}",
                        sender_pk));

            return channel.onRequestUpdateSig(seq_id);
        }

        return Result!Signature(ErrorCode.InvalidChannelID,
            "Channel ID not found");
    }

    /// See `FlashAPI.confirmChannelUpdate`
    public override Result!bool confirmChannelUpdate (PublicKey sender_pk,
        PublicKey recv_pk, /* in */ Hash chan_id, /* in */ uint seq_id) @trusted
    {
        auto secret_key = recv_pk in this.managed_keys;
        if (secret_key is null)
            return Result!bool(ErrorCode.KeyNotRecognized,
                format("The provided key %s is not managed by this "
                ~ "Flash node. Do you have the right address..?", recv_pk));

        if (auto chans = recv_pk in this.channels)
        if (auto channel = chan_id in *chans)
        {
            if (sender_pk != channel.peer_pk)
                return Result!bool(ErrorCode.KeyNotRecognized,
                    format("Sender key does not belong to this channel: {}",
                        sender_pk));

            return channel.onConfirmedChannelUpdate(seq_id);
        }

        return Result!bool(ErrorCode.InvalidChannelID,
            "Channel ID not found");
    }

    /// See `FlashAPI.proposePayment`
    public override Result!PublicNonce proposePayment (PublicKey sender_pk,
        PublicKey recv_pk, /* in */ Hash chan_id, /* in */ uint seq_id,
        /* in */ Hash payment_hash, /* in */ Amount amount,
        /* in */ Height lock_height, /* in */ OnionPacket packet,
        /* in */ PublicNonce peer_nonce, /* in */ Height height) @trusted
    {
        if (packet.version_byte != OnionVersion)
            return Result!PublicNonce(ErrorCode.VersionMismatch,
                "Protocol version mismatch");

        auto chans = recv_pk in this.channels;
        if (chans is null)
            return Result!PublicNonce(ErrorCode.InvalidChannelID,
                "Channel ID not found");

        auto channel = chan_id in *chans;
        if (channel is null)
            return Result!PublicNonce(ErrorCode.InvalidChannelID,
                "Channel ID not found");

        if (!packet.ephemeral_pk.isValid())
            return Result!PublicNonce(ErrorCode.InvalidOnionPacket,
                "Ephemeral public key in the onion packet is invalid");

        auto secret_key = recv_pk in this.managed_keys;
        if (secret_key is null)
            return Result!PublicNonce(ErrorCode.KeyNotRecognized,
                format("The provided key %s is not managed by this Flash node.",
                    recv_pk));

        Payload payload;
        Point shared_secret;
        if (!decryptPayload(packet.encrypted_payloads[0], *secret_key,
            packet.ephemeral_pk, payload, shared_secret))
            return Result!PublicNonce(ErrorCode.InvalidOnionPacket,
                "Cannot decrypt onion packet payload");

        if (payload.next_chan_id != Hash.init
            && payload.next_chan_id !in this.channels[recv_pk])
            return Result!PublicNonce(ErrorCode.InvalidChannelID,
                "Cannot accept this forwarded payment as it routes to an "
                ~ "unrecognized channel ID");

        return channel.onProposedPayment(seq_id, payment_hash, amount,
            lock_height, packet, payload, peer_nonce, height, shared_secret);
    }

    /// See `FlashAPI.proposeUpdate`
    public override Result!PublicNonce proposeUpdate (PublicKey sender_pk,
        PublicKey recv_pk, /* in */ Hash chan_id, /* in */ uint seq_id,
        /* in */ Hash[] secrets, /* in */ Hash[] rev_htlcs,
        /* in */ PublicNonce peer_nonce, /* in */ Height height) @trusted
    {
        if (auto chans = recv_pk in this.channels)
        if (auto channel = chan_id in *chans)
        {
            if (height != this.last_height)
                return Result!PublicNonce(ErrorCode.MismatchingBlockHeight,
                    format("Mismatching block height! Our: %s Their %s",
                        this.last_height, height));

            return channel.onProposedUpdate(seq_id, secrets, rev_htlcs,
                peer_nonce, height);
        }

        return Result!PublicNonce(ErrorCode.InvalidChannelID,
            "Channel ID not found");
    }

    /// See `FlashAPI.reportPaymentError`
    public override void reportPaymentError (
        PublicKey recv_pk, /* in */ Hash chan_id, /* in */ OnionError err)
    {
        import std.algorithm.searching : canFind;

        if (auto path = err.payment_hash in this.payment_path)
        {
            auto shared_secrets = this.shared_secrets[err.payment_hash];
            assert(shared_secrets.length == path.length);

            auto chans = (*path).map!(hop => hop.chan_id);
            OnionError deobfuscated = err;
            size_t failing_hop_idx = shared_secrets.length - 1;
            foreach (idx, secret; shared_secrets)
            {
                if (chans.canFind(deobfuscated.chan_id))
                {
                    failing_hop_idx = idx;
                    break;
                }
                deobfuscated = deobfuscated.obfuscate(secret);
            }
            if (!chans.canFind(deobfuscated.chan_id))
                return;

            // Get the PublicKey of the node we think is failing
            const failing_node_pk = (*path)[failing_hop_idx].pub_key;
            const failing_chan = this.known_channels[deobfuscated.chan_id];
            // Check the failing node is a peer of the failing channel
            if (failing_chan.funder_pk != failing_node_pk &&
                failing_chan.peer_pk != failing_node_pk)
                return;

            log.info(recv_pk.flashPrettify, " Got error: ",
                deobfuscated);
            this.payment_errors[deobfuscated.payment_hash] ~= deobfuscated;
            this.dump();
        }
        else
        {
            if (auto chans = recv_pk in this.channels)
                foreach (id, channel; *chans)
                    if (id != chan_id)
                        channel.forwardPaymentError(err);
        }
    }

    /***************************************************************************

        Called by a channel once a payment has been completed.

        If the there are any known secrets, we can propose an update to the
        channel state by revealing the secrets to the counter-parties.

        Params:
            chan_id = the channel ID for which the payment was completed
            payment_hash = the payment hash which was used

    ***************************************************************************/

    protected void onPaymentComplete (PublicKey reg_pk, Hash chan_id,
        Hash payment_hash, ErrorCode error = ErrorCode.None) @safe
    {
        auto chans = reg_pk in this.channels;
        if (chans is null)
        {
            // todo: assert?
            log.info("Error: Channel not found: {}", chan_id);
            return;
        }

        auto channel = chan_id in *chans;
        if (channel is null)
        {
            // todo: assert?
            log.info("Error: Channel not found: {}", chan_id);
            return;
        }

        // we only report failures here. success is only reported after
        // a successfull update
        if (error != ErrorCode.None)
        {
            if (auto invoice = payment_hash in this.invoices)
                this.listener.onPaymentFailure(reg_pk, *invoice, error);
        }

        // our own secret (we are the payee)
        if (auto secret = payment_hash in this.secrets)
        {
            assert(!error); // Payee should never fail to receive
            channel.learnSecrets([*secret], [], this.last_height);
        }
        else if (error)
        {
            foreach (id, chan; *chans)
                chan.learnSecrets([], [payment_hash], this.last_height);
            this.reportPaymentError(reg_pk, chan_id, OnionError(payment_hash,
                chan_id, error));
        }
    }

    /***************************************************************************

        Called by a channel once an update has been completed.

        For any channels which use the same payment hash, the node will
        try to update the channel by settling the HTLCs.

        Params:
            secrets = list of secrets revealed during an update
            rev_htlcs = list of htlcs dropped during an update

    ***************************************************************************/

    protected void onUpdateComplete (PublicKey reg_pk, in Hash[] secrets,
        in Hash[] rev_htlcs)
    {
        foreach (payment_hash; secrets.map!(secret => secret.hashFull()))
        {
            this.secrets.remove(payment_hash);
            this.shared_secrets.remove(payment_hash);
            this.payment_path.remove(payment_hash);
            this.payment_errors.remove(payment_hash);

            // get the invoice if it exists and not just the pointer (GC safety)
            Invoice inv;
            auto invoice = this.invoices.get(payment_hash, Invoice.init);
            this.invoices.remove(payment_hash);

            if (invoice != Invoice.init)
                this.listener.onPaymentSuccess(reg_pk, invoice);
        }

        foreach (payment_hash; rev_htlcs)
        {
            if (auto invoice = payment_hash in this.invoices)
            {
                ErrorCode error;
                if (auto errors = payment_hash in this.payment_errors)
                    error = (*errors)[$ - 1].err;  // pick latest known reason
                else
                    error = ErrorCode.Unknown;

                this.listener.onPaymentFailure(reg_pk, *invoice, error);
            }
        }

        if (auto chans = reg_pk in this.channels)
        foreach (chan_id, channel; *chans)
        {
            log.info("Calling learnSecrets for {}", chan_id);
            channel.learnSecrets(secrets, rev_htlcs, this.last_height);
        }
    }

    /***************************************************************************

        Routes an onion-encrypted payment to the given channel ID.

        Params:
            reg_pk = the registered public key
            chan_id = the channel ID to route the payment to
            payment_hash = the payment hash to use
            amount = the amount to use
            lock_height = the lock the HTLC will use
            packet = the onion-encrypted packet for the channel counter-party

        Returns:
            Error code

    ***************************************************************************/

    protected void paymentRouter (in PublicKey reg_pk, in Hash chan_id,
        in Hash payment_hash, in Amount amount,
        in Height lock_height, in OnionPacket packet) @safe
    {
        if (auto chans = reg_pk in this.channels)
            if (auto channel = chan_id in *chans)
                return channel.queueNewPayment(payment_hash, amount, lock_height,
                    packet, this.last_height);

        log.info("{} Could not find this channel ID: {}",
            reg_pk.flashPrettify, chan_id);
        this.onPaymentComplete(reg_pk, chan_id, payment_hash,
            ErrorCode.InvalidChannelID);
    }

    ///
    public override Result!bool beginCollaborativeClose (PublicKey reg_pk,
        /* in */ Hash chan_id)
    {
        if (auto chans = reg_pk in this.channels)
            if (auto channel = chan_id in *chans)
                return channel.beginCollaborativeClose(this.listener.getEstimatedTxFee());

        return Result!bool(ErrorCode.InvalidChannelID, "Channel ID not found");
    }

    ///
    public override Result!bool beginUnilateralClose (PublicKey reg_pk,
        /* in */ Hash chan_id)
    {
        if (auto pk_channels = reg_pk in this.channels)
        {
            if (auto channel = chan_id in *pk_channels)
                return channel.beginUnilateralClose();
        }

        return Result!bool(ErrorCode.InvalidChannelID, "Channel ID not found");
    }

    ///
    public override Result!Hash openNewChannel (PublicKey reg_pk,
        /* in */ UTXO funding_utxo, /* in */ Hash funding_utxo_hash,
        /* in */ Amount capacity, /* in */ uint settle_time, /* in */ Point recv_pk)
    {
        log.info("openNewChannel({}, {}, {})",
                 capacity, settle_time, recv_pk.flashPrettify);

        auto secret_key = reg_pk in this.managed_keys;
        if (secret_key is null)
            return Result!Hash(ErrorCode.KeyNotRecognized,
                format("The provided key %s is not managed by this Flash node.",
                    reg_pk));

        if (funding_utxo.output.address != reg_pk)
            return Result!Hash(ErrorCode.RejectedFundingUTXO,
                format("The provided UTXO does not belong to %s",
                    reg_pk));

        if (funding_utxo.output.value < capacity)
            return Result!Hash(ErrorCode.RejectedFundingUTXO,
                format("The provided UTXO does not have requested (%s BOA) funds",
                    capacity));

        const key_pair = () @trusted { return KeyPair.fromSeed(*secret_key); }();
        const pair_pk = key_pair.address + recv_pk;

        // create funding, don't sign it yet as we'll share it first
        auto funding_tx = createFundingTx(funding_utxo, funding_utxo_hash,
            capacity, pair_pk, this.listener.getEstimatedTxFee());

        if (funding_tx == Transaction.init)
            return Result!Hash(ErrorCode.RejectedFundingUTXO,
                format("The provided UTXO does not have requested funds for TX fees"));

        const funding_tx_hash = hashFull(funding_tx);
        const Hash chan_id = funding_tx_hash;

        auto all_funding_utxos = this.pending_channels[reg_pk][].chain(
                this.channels[reg_pk].byValue.map!(chan => chan.conf))
            .map!(conf => conf.funding_tx_hash);

        // this channel is already being set up (or duplicate funding UTXO used)
        if (all_funding_utxos.canFind(funding_tx_hash))
        {
            return Result!Hash(ErrorCode.DuplicateChannelID,
                "Cannot open another channel with the same UTXO as a "
                ~ "pending / existing channel");
        }

        const funding_utxo_idx = funding_tx.outputs.map!(output => output.address).countUntil(pair_pk);
        assert(funding_utxo_idx != -1);
        const num_peers = 2;
        ChannelConfig chan_conf =
        {
            gen_hash        : this.genesis_hash,
            funder_pk       : key_pair.address,
            peer_pk         : recv_pk,
            pair_pk         : key_pair.address + recv_pk,
            num_peers       : num_peers,
            update_pair_pk  : getUpdatePk(pair_pk, funding_tx_hash, num_peers),
            funding_tx      : funding_tx,
            funding_tx_hash : funding_tx_hash,
            funding_utxo_idx: cast (uint) funding_utxo_idx,
            capacity        : capacity,
            settle_time     : settle_time,
        };
        this.pending_channels[reg_pk].insertBack(chan_conf);

        return Result!Hash(chan_id);
    }

    /// Handle opening new channels
    private void handleOpenNewChannel (PublicKey reg_pk, ChannelConfig chan_conf)
    {
        auto peer = this.getFlashClient(chan_conf.peer_pk, this.conf.timeout);
        if (peer is null)
        {
            this.listener.onChannelNotify(reg_pk, chan_conf.chan_id,
                ChannelState.Rejected, ErrorCode.AddressNotFound);
            return;
        }

        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();

        auto result = peer.openChannel(PublicKey(chan_conf.peer_pk), chan_conf,
            pub_nonce);
        if (result.error != ErrorCode.None)
        {
            this.listener.onChannelNotify(reg_pk, chan_conf.chan_id,
                ChannelState.Rejected, result.error);
            return;
        }

        auto secret_key = reg_pk in this.managed_keys;
        if (secret_key is null)
            assert(0);  // should not happen
        const key_pair = KeyPair.fromSeed(*secret_key);

        auto channel = new Channel(this.conf, chan_conf, key_pair,
            priv_nonce, result.value, peer, this.engine, this.taskman,
            &this.putTransaction, &this.paymentRouter, &this.onChannelNotify,
            &this.onPaymentComplete, &this.onUpdateComplete, this.db);
        this.channels[reg_pk][chan_conf.chan_id] = channel;
    }

    ///
    public void waitChannelOpen (PublicKey reg_pk, /* in */ Hash chan_id)
    {
        auto chans = reg_pk in this.channels;
        assert(chans !is null);
        auto channel = chan_id in *chans;
        assert(channel !is null);

        const state = channel.getState();
        if (state >= ChannelState.StartedCollaborativeClose)
        {
            log.info("Error: waitChannelOpen({}) called on channel state {}",
                chan_id.flashPrettify, state);
            return;
        }

        while (!channel.isOpen())
            this.taskman.wait(100.msecs);
    }

    ///
    public override Result!Invoice createNewInvoice (PublicKey reg_pk,
        /* in */ Amount amount, /* in */ time_t expiry,
        /* in */ string description = null)
    {
        log.info("createNewInvoice({}, {}, {})",
            amount, expiry, description);

        if (reg_pk !in this.managed_keys)
            return Result!Invoice(ErrorCode.KeyNotRecognized,
                format("The provided key %s is not managed by this "
                ~ "Flash node. Do you have the right address..?", reg_pk));

        auto pair = createInvoice(reg_pk, amount, expiry, description);
        this.invoices[pair.invoice.payment_hash] = pair.invoice;
        this.secrets[pair.invoice.payment_hash] = pair.secret;
        this.dump();

        return Result!Invoice(pair.invoice);
    }

    /// Finds a payment path for the invoice and attempts to pay it
    public override void payInvoice (PublicKey reg_pk, /* in */ Invoice invoice)
    {
        auto secret_key = reg_pk in this.managed_keys;
        if (secret_key is null)
            assert(0);  // todo: return error code

        if (!this.isValidInvoice(reg_pk, invoice))
            assert(0);  // todo: should just reject it when we write test for it

        Set!Hash ignore_chans;
        if (auto error = invoice.payment_hash in this.payment_errors)
            ignore_chans = Set!Hash.from((*error).map!(err => err.chan_id));

        auto path = this.network.getPaymentPath(reg_pk,
            invoice.destination, invoice.amount, ignore_chans);
        if (path.length < 1 || path.length > MaxPathLength)
        {
            this.listener.onPaymentFailure(reg_pk, invoice, ErrorCode.PathNotFound);
            return;
        }

        Amount total_amount;
        Height use_lock_height;
        Point[] cur_shared_secrets;
        auto packet = createOnionPacket(invoice.payment_hash, invoice.amount,
            path, total_amount, use_lock_height, cur_shared_secrets);
        this.shared_secrets[invoice.payment_hash] = cur_shared_secrets.reverse;
        this.payment_path[invoice.payment_hash] = path;
        this.invoices[invoice.payment_hash] = invoice;

        // If suggested lock height is not enough, use settle_time + htlc_delta
        auto first_conf = this.known_channels[path.front.chan_id];
        auto first_update = this.channels[reg_pk][path.front.chan_id]
            .getChannelUpdate();
        use_lock_height = max(use_lock_height,
            Height(first_conf.settle_time + first_update.htlc_delta));

        use_lock_height = Height(use_lock_height + this.last_height);

        this.paymentRouter(reg_pk, path.front.chan_id, invoice.payment_hash,
            total_amount, use_lock_height, packet);
        this.dump();
    }

    ///
    private bool isValidInvoice (PublicKey pk, /* in */ Invoice invoice) @safe
    {
        // paying to ourself doesn't make sense
        if (invoice.destination == pk)
            return false;

        return true;
    }
}

/// All the node metadata which we keep in the DB for storage
private mixin template NodeMetadata ()
{
    /// List of currently managed key-pairs
    protected SecretKey[PublicKey] managed_keys;

    /// These are the known channels of which we may not necessary be a
    /// counterparty of. With this information we can derive payment paths.
    protected ChannelConfig[Hash] known_channels;

    /// Most recent update received for this channel
    protected ChannelUpdate[PaymentDirection][Hash] channel_updates;

    /// The last read block height.
    protected Height last_height;

    /// secret hash => secret (preimage)
    /// Only the Payee initially knows about the secret,
    /// but is then revealed back towards the payer through
    /// any intermediaries.
    protected Hash[Hash] secrets;

    /// Shared secrets used to encrypt the OnionPacket
    protected Point[][Hash] shared_secrets;

    /// Path that is currently being tried for a payment
    protected Hop[][Hash] payment_path;

    /// Errors that are received for payments
    protected OnionError[][Hash] payment_errors;

    /// hash of secret => Invoice
    private Invoice[Hash] invoices;
}

/// A thin Flash node which itself is not a FullNode / Validator but instead
/// interacts with another FullNode / Validator for queries to the blockchain.
public abstract class ThinFlashNode : FlashNode
{
    /// random agora node (for sending tx's)
    protected FullNodeAPI agora_node;

    /// monitor timer
    protected ITimer monitor_timer;

    /***************************************************************************

        Constructor

        Params:
            conf = Flash configuration
            db_path = path to the database (or in-memory if set to ":memory:")
            genesis_hash = the hash of the genesis block to use
            engine = the execution engine to use
            taskman = the task manager ot use
            agora_address = IP address of an Agora node to monitor the
                blockchain and publish new on-chain transactions to it.

    ***************************************************************************/

    public this (FlashConfig conf, string db_path, Hash genesis_hash,
        Engine engine, ITaskManager taskman, string agora_address)
    {
        this.agora_node = this.getAgoraClient(agora_address, conf.timeout);
        super(conf, db_path, genesis_hash, engine, taskman);
    }

    /***************************************************************************

        Start monitoring the blockchain for any new externalized blocks.

    ***************************************************************************/

    public override void start () @trusted
    {
        // todo: 20 msecs is ok only in tests
        // todo: should additionally register as pushBlock() listener
        this.monitor_timer = this.taskman.setTimer(20.msecs,
            &this.monitorBlockchain, Periodic.Yes);
        super.start();
    }

    /***************************************************************************

        Shut down any timers and store latest data to the database

    ***************************************************************************/

    public override void shutdown ()
    {
        super.shutdown();
        if (this.monitor_timer !is null)
            this.monitor_timer.stop();
    }

    /***************************************************************************

        Monitors the blockchain for any new externalized blocks.

        If a funding / closing / trigger / update / settlement transaction
        belong to a channel is detected, it will trigger that channel's
        handler for this event.

        This enables changing the channel's state from open to closed.

    ***************************************************************************/

    private void monitorBlockchain ()
    {
        try
        {
            auto latest_height = this.agora_node.getBlockHeight();
            if (this.last_height < latest_height)
            {
                auto next_block = this.agora_node.getBlocksFrom(
                    this.last_height + 1, 1)[0];

                foreach (reg_pk, chans; this.channels)
                    foreach (channel; chans)
                        channel.onBlockExternalized(next_block);

                this.last_height++;
                this.dump();
            }
        }
        catch (Exception ex)
        {
            // connection might be dropped
        }
    }

    /***************************************************************************

        Get an instance of an Agora client.

        Params:
            address = The address (IPv4, IPv6, hostname) of the Agora node.
            timeout = the timeout duration to use for requests.

        Returns:
            the Agora FullNode client

    ***************************************************************************/

    protected FullNodeAPI getAgoraClient (Address address, Duration timeout)
    {
        import vibe.http.client;

        auto settings = new RestInterfaceSettings;
        settings.baseURL = URL(address);
        settings.httpClientSettings = new HTTPClientSettings;
        settings.httpClientSettings.connectTimeout = timeout;
        settings.httpClientSettings.readTimeout = timeout;

        return new RestInterfaceClient!FullNodeAPI(settings);
    }

    /***************************************************************************

        Send the transaction via the connected agora node.

        Params:
            tx = the transaction to send

    ***************************************************************************/

    protected override void putTransaction (Transaction tx)
    {
        this.agora_node.putTransaction(tx);
    }
}

/// A FullNode / Validator should embed this class if they enabled Flash
public class AgoraFlashNode : FlashNode
{
    /// Callback for sending transactions to the network
    protected void delegate (Transaction tx) putTransactionDg;

    /// Network manager
    protected NetworkManager network;

    /// Periodic name registry timer
    protected ITimer periodic_timer;

    /// Registry client
    private NameRegistryAPI registry_client;

    /***************************************************************************

        Constructor

        Params:
            conf = Flash configuration
            data_dir = path to the data directory
            genesis_hash = the hash of the genesis block to use
            engine = the execution engine to use
            taskman = the task manager ot use
            putTransactionDg = callback for sending transactions to the network
            network = NetworkManager which contains the name registry

    ***************************************************************************/

    public this (FlashConfig conf, string data_dir, Hash genesis_hash,
        Engine engine, ITaskManager taskman,
        void delegate (Transaction tx) putTransactionDg,
        NetworkManager network)
    {
        const db_path = buildPath(data_dir, "flash.dat");
        this.putTransactionDg = putTransactionDg;
        this.network = network;
        super(conf, db_path, genesis_hash, engine, taskman);
    }

    /***************************************************************************

        Start timers and register with the name registry.

    ***************************************************************************/

    public override void start () @trusted
    {
        super.start();
        this.startNameRegistry();
    }

    /***************************************************************************

        Shutdown all timers.

    ***************************************************************************/

    public override void shutdown ()
    {
        super.shutdown();
        this.periodic_timer.stop();
    }

    /***************************************************************************

        Start listening for requests

        Begins asynchronous tasks for the Flash ControlAPI interface

    ***************************************************************************/

    public HTTPListener startControlInterface ()
    {
        this.start();

        if (!this.conf.enabled)
            assert(0, "Flash interface is not enabled in config settings.");

        auto settings = new HTTPServerSettings(this.conf.control_address);
        settings.port = this.conf.control_port;

        auto router = new URLRouter();
        router.registerRestInterface!FlashControlAPI(this);

        return listenHTTP(settings, router);
    }

    /// Called by a FullNode once a block has been externalized
    public void onExternalizedBlock (const ref Block block) @safe
    {
        this.last_height = block.header.height;

        foreach (reg_pk, chans; this.channels)
            foreach (channel; chans)
                channel.onBlockExternalized(block);
    }

    // start the periodic name registry routine
    private void startNameRegistry ()
    {
        this.onRegisterName();  // avoid delay
        this.periodic_timer = this.taskman.setTimer(2.minutes,
            &this.onRegisterName, Periodic.Yes);
    }

    /// register network addresses into the name registry
    private void onRegisterName ()
    {
        if (this.registry_client is null)  // try to get the client
            this.registry_client = this.network.getNameRegistryClient(
                this.conf.registry_address, 10.seconds);

        if (this.registry_client is null)
            return;  // failed, try again later

        const(Address)[] addresses = this.conf.addresses_to_register;
        if (!addresses.length)
            addresses = InetUtils.getPublicIPs();

        foreach (pair; this.getManagedKeys())
        {
            RegistryPayload payload =
            {
                data:
                {
                    public_key : pair.key,
                    addresses : addresses,
                    seq : time(null)
                }
            };

            const key_pair = KeyPair.fromSeed(pair.value);
            payload.signPayload(key_pair);

            try
            {
                this.registry_client.putValidator(payload);
            }
            catch (Exception ex)
            {
                log.info("Couldn't register our address: {}. Trying again later..",
                    ex);
            }
        }
    }

    /***************************************************************************

        Send the transaction via the connected agora node.

        Params:
            tx = the transaction to send

    ***************************************************************************/

    protected override void putTransaction (Transaction tx)
    {
        this.putTransactionDg(tx);
    }

    /***************************************************************************

        Get an instance of a Flash client for the given public key.
        The name registry is consulted to look up the IP for the given key.

        The client is cached internally.

        Params:
            peer_pk = the public key of the Flash node.
            timeout = the timeout duration to use for requests.

        Returns:
            the Flash client, or null if none was found

    ***************************************************************************/

    protected override FlashAPI getFlashClient (in PublicKey peer_pk,
        Duration timeout) @trusted
    {
        if (auto peer = peer_pk in this.known_peers)
            return *peer;

        log.info("getFlashClient searching peer: {}", peer_pk);

        auto payload = this.registry_client.getValidator(peer_pk);
        if (payload == RegistryPayload.init)
        {
            log.warn("Could not find mapping in registry for key {}", peer_pk);
            return null;
        }

        if (!payload.verifySignature(peer_pk))
        {
            log.warn("RegistryPayload signature is incorrect for {}", peer_pk);
            return null;
        }

        if (payload.data.addresses.length == 0)
            return null;

        string ip = payload.data.addresses[0];

        import vibe.http.client;

        auto settings = new RestInterfaceSettings;
        // todo: this is obviously wrong, need proper connection handling later
        settings.baseURL = URL(ip);
        settings.httpClientSettings = new HTTPClientSettings;
        settings.httpClientSettings.connectTimeout = timeout;
        settings.httpClientSettings.readTimeout = timeout;

        auto peer = new RestInterfaceClient!FlashAPI(settings);
        this.known_peers[peer_pk] = peer;
        if (this.known_channels.length > 0)
        {
            peer.gossipChannelsOpen(this.known_channels.values);
            peer.gossipChannelUpdates(this.channel_updates.byValue
                .map!(updates => updates.byValue).joiner.array);
        }

        return peer;
    }

    /***************************************************************************

        Get an instance of a FlashListenerAPI client for the given address.

        Params:
            address = the IP to use
            timeout = the timeout duration to use for requests

        Returns:
            the FlashListenerAPI client

    ***************************************************************************/

    protected override FlashListenerAPI getFlashListenerClient (
        string address, Duration timeout) @trusted
    {
        import vibe.http.client;

        auto settings = new RestInterfaceSettings;
        settings.baseURL = URL(address);
        settings.httpClientSettings = new HTTPClientSettings;
        settings.httpClientSettings.connectTimeout = timeout;
        settings.httpClientSettings.readTimeout = timeout;

        return new RestInterfaceClient!FlashListenerAPI(settings);
    }
}
