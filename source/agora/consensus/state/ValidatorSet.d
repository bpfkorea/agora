/*******************************************************************************

    Contains supporting code for managing validators' information
    using SQLite as a backing store, including the enrolled height
    which means enrollment process is confirmed as part of consensus.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.state.ValidatorSet;

import agora.common.crypto.ECC;
import agora.common.crypto.Key;
import agora.common.crypto.Schnorr;
import agora.common.Hash;
import agora.common.ManagedDatabase;
import agora.common.Serializer;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Params;
import agora.consensus.data.PreImageInfo;
import agora.consensus.PreImage;
import agora.consensus.state.UTXOSet;
import agora.consensus.validation;
import agora.utils.Log;
version (unittest) import agora.utils.Test;

import d2sqlite3.library;
import d2sqlite3.results;
import d2sqlite3.sqlite3;

mixin AddLogger!();

/// Ditto
public class ValidatorSet
{
    /// SQLite db instance
    private ManagedDatabase db;

    /// Parameters for consensus-critical constants
    private immutable(ConsensusParams) params;

    /***************************************************************************

        Constructor

        Params:
            db = the managed database instance
            params = the consensus-critical constants

    ***************************************************************************/

    public this (ManagedDatabase db, immutable(ConsensusParams) params)
    {
        this.db = db;
        this.params = params;

        // create the table for validator set if it doesn't exist yet
        this.db.execute("CREATE TABLE IF NOT EXISTS validator_set " ~
            "(key TEXT PRIMARY KEY, public_key TEXT, " ~
            "cycle_length INTEGER, enrolled_height INTEGER, " ~
            "distance INTEGER, preimage TEXT)");
    }

    /***************************************************************************

        Add a enrollment data to the validators set

        Params:
            block_height = the current block height in the ledger
            finder = the delegate to find UTXOs with
            enroll = the enrollment data to add
            pubkey = the public key of the enrollment

        Returns:
            A string describing the error, or `null` on success

    ***************************************************************************/

    public string add (Height block_height, scope UTXOFinder finder,
        const ref Enrollment enroll, PublicKey pubkey) @safe nothrow
    {
        // check validaty of the enrollment data
        if (auto reason = isInvalidReason(enroll, finder))
            return reason;

        // check if already exists
        if (this.hasEnrollment(enroll.utxo_key))
            return "This validator is already enrolled";

        // check if an enrollment of the same public key is already present
        if (this.hasPublicKey(pubkey))
            return "An validator with the same public key is already enrolled";

        try
        {
            () @trusted {
                const ZeroDistance = 0;  // initial distance
                this.db.execute("INSERT INTO validator_set " ~
                    "(key, public_key, cycle_length, enrolled_height, " ~
                    "distance, preimage) VALUES (?, ?, ?, ?, ?, ?)",
                    enroll.utxo_key.toString(),
                    pubkey.toString(),
                    enroll.cycle_length, block_height.value, ZeroDistance,
                    enroll.random_seed.toString());
            }();
        }
        catch (Exception ex)
        {
            // This should never happen, hence why we log it as well
            log.error("Unexpected error while adding a validator: {} ({})",
                      ex, enroll);
            return "Internal error in `ValidatorSet.add`";
        }

        return null;
    }

    /***************************************************************************

        Returns:
            the number of active enrollments, or 0 if there was a database error

    ***************************************************************************/

    public size_t count () @trusted nothrow
    {
        try
        {
            return this.db.execute("SELECT count(*) FROM validator_set").
                oneValue!size_t;
        }
        catch (Exception ex)
        {
            log.error("Error while calling ValidatorSet.count(): {}", ex);
            return 0;
        }
    }

    /***************************************************************************

        Remove the enrollment data with the given UTXO key from the validator set

        Params:
            utxo_key = the UTXO key of the enrollment data to remove

    ***************************************************************************/

    public void remove (in Hash enroll_hash) @trusted nothrow
    {
        try
        {
            this.db.execute("DELETE FROM validator_set WHERE key = ?",
                enroll_hash.toString());
        }
        catch (Exception ex)
        {
            log.error("Error while calling ValidatorSet.remove(): {}", ex);
        }
    }

    /***************************************************************************

        Remove all validators from the validator set

    ***************************************************************************/

    public void removeAll () @trusted nothrow
    {
        try
        {
            this.db.execute("DELETE FROM validator_set");
        }
        catch (Exception ex)
        {
            log.error("Error while calling ValidatorSet.removeAll(): {}", ex);
        }
    }

    /***************************************************************************

        In validatorSet DB, return the enrolled block height.

        Params:
            enroll_hash = key for an enrollment block height

        Returns:
            the enrolled block height, or `ulong.max` if no matching key exists

    ***************************************************************************/

    public Height getEnrolledHeight (in Hash enroll_hash) @trusted nothrow
    {
        try
        {
            auto results = this.db.execute("SELECT enrolled_height FROM validator_set" ~
                " WHERE key = ?", enroll_hash.toString());
            if (results.empty)
                return Height(ulong.max);

            return Height(results.oneValue!(size_t));
        }
        catch (Exception ex)
        {

            log.error("ManagedDatabase operation error: {}", ex.msg);
            return Height(ulong.max);
        }
    }

    /***************************************************************************

        In validatorSet DB, return the cycle length.

        Params:
            enroll_hash = key for an enrollment

        Returns:
            the cycle length, or `uint.max` if no matching key exists

    ***************************************************************************/

    public uint getCycleLength (in Hash enroll_hash) @trusted nothrow
    {
        try
        {
            auto results = this.db.execute("SELECT cycle_length FROM validator_set" ~
                " WHERE key = ?", enroll_hash.toString());
            if (!results.empty)
                return results.oneValue!(uint);
        }
        catch (Exception ex)
        {

            log.error("ManagedDatabase operation error: {}", ex.msg);
        }
        return uint.max;
    }

    /***************************************************************************

        Check if a enrollment data exists in the validator set.

        Params:
            enroll_hash = key for an enrollment data which is hash of frozen UTXO

        Returns:
            true if the validator set has the enrollment data

    ***************************************************************************/

    public bool hasEnrollment (in Hash enroll_hash) @trusted nothrow
    {
        try
        {
            auto results = this.db.execute("SELECT EXISTS(SELECT 1 FROM " ~
                "validator_set WHERE key = ?)", enroll_hash.toString());
            return results.front().peek!bool(0);
        }
        catch (Exception ex)
        {
            log.fatal("Exception occured on hasEnrollment: {}, " ~
                "Key for enrollment: {}", ex.msg, enroll_hash);
            assert(0);
        }
    }

    /***************************************************************************

        Check with public key if a enrollment data exists in the validator set

        Params:
            pubkey = the key by which the validator set searches enrollment

        Returns:
            true if the validator set has an enrollment for the public key

    ***************************************************************************/

    public bool hasPublicKey (in PublicKey pubkey) @trusted nothrow
    {
        try
        {
            auto results = this.db.execute("SELECT EXISTS(SELECT 1 FROM " ~
                "validator_set WHERE public_key = ?)", pubkey.toString());
            return results.front().peek!bool(0);
        }
        catch (Exception ex)
        {
            log.fatal("Exception occured on hasEnrollment: {}, " ~
                "PublicKey for enrollment: {}", ex.msg, pubkey);
            assert(0);
        }
    }

    /***************************************************************************

        Get all the current validators in ascending order with the utxo_key

        Params:
            validators = will be filled with all the validators during
                their validation cycles

        Returns:
            Return true if there was no error in getting the UTXO keys

    ***************************************************************************/

    public bool getEnrolledUTXOs (out Hash[] utxo_keys) @trusted nothrow
    {
        try
        {
            auto results = this.db.execute("SELECT key " ~
                "FROM validator_set ORDER BY key ASC");
            foreach (row; results)
                utxo_keys ~= Hash(row.peek!(char[])(0));
            return true;
        }
        catch (Exception ex)
        {
            log.error("ManagedDatabase operation error: {}", ex.msg);
            return false;
        }
    }

    /***************************************************************************

        Clear up expired validators whose cycle for a validator ends

        The validator set clears up expired validators from the set based on
        the block height. Validators are deleted if their enrolled height is
        less than or equal to the value of the passed block height minus the
        validator cycle.

        Params:
            block_height = current block height

    ***************************************************************************/

    public void clearExpiredValidators (Height block_height) @safe nothrow
    {
        try
        {
            () @trusted {
                this.db.execute("DELETE FROM validator_set WHERE " ~
                    "enrolled_height + cycle_length <= ?", block_height.value);
            }();
        }
        catch (Exception ex)
        {
            log.error("ManagedDatabase operation error: {}", ex.msg);
        }
    }

    /***************************************************************************

        Gets the number of active validators at the block height.

        `block_height` is the height of the newly created block.
        If the active validators are less than the specified value,
        new blocks cannot be created.

        Params:
            block_height = the height of proposed block

        Returns:
            Returns the number of active validators when the block height is
            `block_height`.
            Returns 0 in case of error.

    ***************************************************************************/

    public ulong getValidatorCount (Height block_height) @safe nothrow
    {
        try
        {
            return () @trusted {
                return this.db.execute(
                    "SELECT count(*) FROM validator_set WHERE " ~
                    "enrolled_height + cycle_length > ?",
                    block_height.value).oneValue!ulong;
            }();
        }
        catch (Exception ex)
        {
            log.error("Database operation error {}", ex);
        }

        return 0;
    }

    /***************************************************************************

        Check if a pre-image exists

        Params:
            enroll_key = The key for the enrollment in which the pre-image is
                contained.
            distance = The minimum expected distance to the commitment

        Returns:
            true if the pre-image exists

    ***************************************************************************/

    public bool hasPreimage (in Hash enroll_key, ushort distance) @safe
        nothrow
    {
        try
        {
            return () @trusted {
                auto results = this.db.execute("SELECT EXISTS(SELECT 1 FROM " ~
                    "validator_set WHERE key = ? AND distance >= ?)",
                    enroll_key.toString(), distance);
                return results.front.peek!bool(0);
            }();
        }
        catch (Exception ex)
        {
            log.error("Exception occured on hasPreimage: {}, " ~
                "Key for enrollment: {}", ex.msg, enroll_key);
            return false;
        }
    }

    /***************************************************************************

        Get validator's pre-image from the validator set

        Params:
            enroll_key = The key for the enrollment in which the pre-image is
                contained.

        Returns:
            the PreImageInfo of the enrolled key if it exists,
            otherwise PreImageInfo.init

    ***************************************************************************/

    public PreImageInfo getPreimage (in Hash enroll_key) @trusted nothrow
    {
        try
        {
            auto results = this.db.execute("SELECT preimage, distance FROM " ~
                "validator_set WHERE key = ?", enroll_key.toString());

            if (!results.empty && results.oneValue!(byte[]).length != 0)
            {
                auto row = results.front;
                Hash preimage = Hash(row.peek!(char[])(0));
                ushort distance = row.peek!ushort(1);
                return PreImageInfo(enroll_key, preimage, distance);
            }
        }
        catch (Exception ex)
        {
            log.error("Exception occured on getPreimage: {}, " ~
                "Key for enrollment: {}", ex.msg, enroll_key);
        }

        return PreImageInfo.init;
    }

    /***************************************************************************

        Get validator's pre-image for the given block height from the
        validator set

        Params:
            enroll_key = The key for the enrollment in which the pre-image is
                contained.
            height = the desired preimage block height. If it's older than
                     the preimage's current block height, the preimage will
                     be hashed until the older preimage is retrieved.
                     Otherwise PreImageInfo.init is returned.

        Returns:
            the PreImageInfo of the enrolled key if it exists,
            otherwise PreImageInfo.init

    ***************************************************************************/

    public PreImageInfo getPreimageAt (in Hash enroll_key, in Height height)
        @trusted nothrow
    {
        try
        {
            auto results = this.db.execute(
                "SELECT preimage, enrolled_height, distance " ~
                "FROM validator_set WHERE key = ? AND enrolled_height <= ? " ~
                "AND enrolled_height + distance >= ?",
                enroll_key.toString(), height.value, height.value);

            if (!results.empty && results.oneValue!(byte[]).length != 0)
            {
                auto row = results.front;
                Hash preimage = Hash(row.peek!(char[])(0));
                Height enrolled_height = Height(row.peek!ulong(1));
                ushort distance = row.peek!ushort(2);

                // go back to the desired preimage of a previous height
                while (enrolled_height + distance > height)
                {
                    preimage = hashFull(preimage);
                    distance--;
                }

                return PreImageInfo(enroll_key, preimage, distance);
            }
        }
        catch (Exception ex)
        {
            log.error("Exception occured in getPreimageAt: {}, " ~
                "Key for enrollment: {}", ex.msg, enroll_key);
        }

        return PreImageInfo.init;
    }

    /***************************************************************************

        Add a pre-image information to a validator data

        Params:
            preimage = the pre-image information to add

        Returns:
            true if the pre-image information has been added to the validator

    ***************************************************************************/

    public bool addPreimage (const ref PreImageInfo preimage) @trusted nothrow
    {
        const prev_preimage = this.getPreimage(preimage.enroll_key);

        if (prev_preimage == PreImageInfo.init)
        {
            log.info("Rejected pre-image: validator not enrolled for key: {}",
                preimage.hash);
            return false;
        }

        const validator_cycle = this.getCycleLength(preimage.enroll_key);

        // Ignore same height pre-image because validators will gossip them
        if (prev_preimage.distance == preimage.distance)
            return false;

        if (auto reason = isInvalidReason(preimage, prev_preimage, validator_cycle))
        {
            log.info("Invalid pre-image data: {}. Pre-image: {}",
                reason, preimage);
            return false;
        }

        // update the preimage info
        try
        {
            () @trusted {
                this.db.execute("UPDATE validator_set SET preimage = ?, " ~
                    "distance = ? WHERE key = ?",
                    preimage.hash.toString(), preimage.distance,
                    preimage.enroll_key.toString());
            }();
        }
        catch (Exception ex)
        {
            log.error("ManagedDatabase operation error on addPreimage: {}, Preimage: {}",
                ex.msg, preimage);
            return false;
        }

        return true;
    }
}

version (unittest)
private Enrollment createEnrollment(in Hash utxo_key,
    const KeyPair key_pair, ref Scalar random_seed_src,
    uint validator_cycle)
{
    import std.algorithm;

    Pair pair = Pair.fromScalar(secretKeyToCurveScalar(key_pair.secret));

    auto enroll = Enrollment();
    auto signature_noise = Pair.random();
    auto cache = PreImageCache(validator_cycle, 1);
    cache.reset(hashFull(random_seed_src));

    enroll.utxo_key = utxo_key;
    enroll.cycle_length = validator_cycle;
    enroll.random_seed = cache[$ - 1];
    enroll.enroll_sig = sign(pair.v, pair.V, signature_noise.V,
        signature_noise.v, enroll);
    return enroll;
}

/// test for functions of ValidatorSet
unittest
{
    import agora.consensus.data.Transaction;
    import std.algorithm;
    import std.range;

    scope storage = new TestUTXOSet;
    scope set = new ValidatorSet(new ManagedDatabase(":memory:"),
        new immutable(ConsensusParams)());

    Hash[] utxos;
    genesisSpendable().take(8).enumerate
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign(TxType.Freeze))
        .each!((tx) {
            storage.put(tx);
            utxos ~= UTXO.getHash(tx.hashFull(), 0);
        });

    // add enrollments
    Scalar[Hash] seed_sources;
    seed_sources[utxos[0]] = Scalar.random();
    auto enroll = createEnrollment(utxos[0], WK.Keys[0], seed_sources[utxos[0]],
        set.params.ValidatorCycle);
    assert(set.add(Height(1), &storage.peekUTXO, enroll, WK.Keys[0].address) is null);
    assert(set.count() == 1);
    assert(set.hasEnrollment(utxos[0]));
    assert(set.add(Height(1), &storage.peekUTXO, enroll, WK.Keys[0].address) !is null);

    seed_sources[utxos[1]] = Scalar.random();
    auto enroll2 = createEnrollment(utxos[1], WK.Keys[1], seed_sources[utxos[1]],
        set.params.ValidatorCycle);
    assert(set.add(Height(1), &storage.peekUTXO, enroll2, WK.Keys[1].address) is null);
    assert(set.count() == 2);

    seed_sources[utxos[2]] = Scalar.random();
    auto enroll3 = createEnrollment(utxos[2], WK.Keys[2], seed_sources[utxos[2]],
        set.params.ValidatorCycle);
    assert(set.add(Height(9), &storage.peekUTXO, enroll3, WK.Keys[2].address) is null);
    assert(set.count() == 3);

    // check if enrolled heights are not set
    Hash[] keys;
    set.getEnrolledUTXOs(keys);
    assert(keys.length == 3);
    assert(keys.isStrictlyMonotonic!("a < b"));

    // remove ValidatorSet
    set.remove(utxos[1]);
    assert(set.count() == 2);
    assert(set.hasEnrollment(utxos[0]));
    set.remove(utxos[0]);
    assert(!set.hasEnrollment(utxos[0]));
    set.removeAll();
    assert(set.count() == 0);

    Enrollment[] ordered_enrollments;
    ordered_enrollments ~= enroll;
    ordered_enrollments ~= enroll2;
    ordered_enrollments ~= enroll3;
    /// PreImageCache for the first enrollment
    PreImageCache cache = PreImageCache(set.params.ValidatorCycle, 1);
    cache.reset(hashFull(seed_sources[utxos[0]]));

    // Reverse ordering
    ordered_enrollments.sort!("a.utxo_key > b.utxo_key");
    foreach (i, ordered_enroll; ordered_enrollments)
        assert(set.add(Height(1), storage.getUTXOFinder(), ordered_enroll, WK.Keys[i].address) is null);
    set.getEnrolledUTXOs(keys);
    assert(keys.length == 3);
    assert(keys.isStrictlyMonotonic!("a < b"));

    // test for adding and getting preimage
    assert(!set.hasPreimage(utxos[0], 10));
    assert(set.getPreimage(utxos[0])
        == PreImageInfo(enroll.utxo_key, enroll.random_seed, 0));
    auto preimage = PreImageInfo(utxos[0], cache[$ - 11], 10);
    assert(set.addPreimage(preimage));
    assert(set.hasPreimage(utxos[0], 10));
    assert(set.getPreimage(utxos[0]) == preimage);
    assert(set.getPreimageAt(utxos[0], Height(0))  // N/A: enrolled at height 1!
        == PreImageInfo.init);
    assert(set.getPreimageAt(utxos[0], Height(12))  // N/A: not revealed yet!
        == PreImageInfo.init);
    assert(set.getPreimageAt(utxos[0], Height(1))
        == PreImageInfo(enroll.utxo_key, enroll.random_seed, 0));
    assert(set.getPreimageAt(utxos[0], Height(11)) == preimage);
    assert(set.getPreimageAt(utxos[0], Height(10)) ==
        PreImageInfo(preimage.enroll_key, hashFull(preimage.hash),
            cast(ushort)(preimage.distance - 1)));

    // test for clear up expired validators
    seed_sources[utxos[3]] = Scalar.random();
    enroll = createEnrollment(utxos[3], WK.Keys[3], seed_sources[utxos[3]],
        set.params.ValidatorCycle);
    assert(set.add(Height(9), &storage.peekUTXO, enroll, WK.Keys[3].address) is null);
    set.clearExpiredValidators(Height(set.params.ValidatorCycle + 8));
    keys.length = 0;
    assert(set.getEnrolledUTXOs(keys));
    assert(keys.length == 1);
    assert(keys[0] == utxos[3]);

    // add enrollment at the genesis block:
    // validates blocks [1 .. set.params.ValidatorCycle] inclusively
    set.clearExpiredValidators(Height(long.max));  // clear all
    assert(set.count == 0);
    seed_sources[utxos[0]] = Scalar.random();
    enroll = createEnrollment(utxos[0], WK.Keys[0], seed_sources[utxos[0]],
        set.params.ValidatorCycle);
    assert(set.add(Height(0), &storage.peekUTXO, enroll, WK.Keys[0].address) is null);

    // not cleared yet at height set.params.ValidatorCycle - 1
    set.clearExpiredValidators(Height(set.params.ValidatorCycle - 1));
    keys.length = 0;
    assert(set.count == 1);
    assert(set.getEnrolledUTXOs(keys));
    assert(keys.length == 1);
    assert(keys[0] == utxos[0]);

    // cleared after block height set.params.ValidatorCycle was externalized
    set.clearExpiredValidators(Height(set.params.ValidatorCycle));
    assert(set.count == 0);
    assert(set.getEnrolledUTXOs(keys));
    assert(keys.length == 0);

    // now try with validator for [1 .. set.params.ValidatorCycle + 1]
    seed_sources[utxos[0]] = Scalar.random();
    enroll = createEnrollment(utxos[0], WK.Keys[0], seed_sources[utxos[0]],
        set.params.ValidatorCycle);
    assert(set.add(Height(1), &storage.peekUTXO, enroll, WK.Keys[0].address) is null);

    // not cleared yet at height set.params.ValidatorCycle
    set.clearExpiredValidators(Height(set.params.ValidatorCycle));
    keys.length = 0;
    assert(set.count == 1);
    assert(set.getEnrolledUTXOs(keys));
    assert(keys.length == 1);
    assert(keys[0] == utxos[0]);

    // cleared after block height set.params.ValidatorCycle was externalized
    set.clearExpiredValidators(Height(set.params.ValidatorCycle + 1));
    assert(set.count == 0);
    assert(set.getEnrolledUTXOs(keys));
    assert(keys.length == 0);
}
