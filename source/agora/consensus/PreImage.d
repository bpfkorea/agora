/*******************************************************************************

    Hold pre-image related utilities

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.PreImage;

import agora.common.Types;
import agora.crypto.ECC;
import agora.crypto.Hash;

/*******************************************************************************

    Helper struct to manage a range of pre-images

    When dealing with pre-images, the only unrecoverable data is the seed.
    Everything else is, by definition, derived from the seed.
    As a result, we can compress the data as much as we want,
    to reduce memory usage. However, this comes at the cost of more computation.

    For example, if we have cycles of 10 pre-images, we can first compute the
    seed (H0), then reveal our initial commitment (H9). This will cost us
    9 hash operations. Then on the next reveal, in order to get H8, we need to
    perform 8 hash operations, then 7 for H7, etc...

    If we want to improve this, we can store intermediate results:
    when generating H9, we do perform 9 hash operations, but store H5.
    Hence, when generating H8 and H7, we only need to perform
    3 and 2 hash operations, respectively, and will never need to perform more
    than 4 operations (save the initial commitment).

    This structure is a mean to generalize this approach, with arbitrary count
    and arbitrary sample size (interval, or distance, between saved pre-images).

*******************************************************************************/

public struct PreImageCache
{
    @safe:

    /// Describe print modes for `toString`
    public enum PrintMode
    {
        /// Print the two extreme values
        Bounds,
        /// Print all stored intermediate value and the last bound
        Stride,
        /// Print all values, performing intermediate hashing
        All,
    }

    /***************************************************************************

        Print the content of a cache

        By default, this function prints the bounds of the cache (the value at
        index 0, and the last value, as returned by `reset`).
        Changing the mode makes it print either the internal content, or the
        full range that is covered, in a newline-separated list.
        Those two later mode are intended for debugging. The parameterless
        `toString` overload is not implemented for this reason.

        Params:
          sink = The sink to write the piecemeal string data to
          mode = The `PrintMode` to use for printing the content.
                 By default, only the bounds (0 and $) are printed.

    ***************************************************************************/

    public void toString (scope void delegate(scope const(char)[]) @safe sink,
                          PrintMode mode = PrintMode.Bounds) const @safe
    {
        final switch (mode)
        {
        case PrintMode.Bounds:
            this[0].toString(sink);
            sink(" - ");
            this[$ - 1].toString(sink);
            break;

        case PrintMode.Stride:
            foreach (index, const ref value; this.data)
            {
                if (index > 0) sink("\n");
                value.toString(sink);
            }
            break;

        case PrintMode.All:
            foreach (index; 0 .. this.length)
            {
                if (index > 0) sink("\n");
                this[index].toString(sink);
                if ((index % this.interval) == 0)
                    sink(" [STORED]");
            }
            break;
        }
    }

    nothrow:

    /// Store the actual preimages
    private Hash[] data;

    /// Interval between two preimages in `data`
    private const ulong interval;

    /// Default-initialized `PreImageCache` is not valid, make sure it can't
    /// be accidentally constructed (e.g. by embbeding it in another aggregate)
    @disable public this ();

    /// Construct an instance using already existing data
    public this (inout(Hash)[] data_, ulong sample_size) inout @nogc pure
    {
        assert(sample_size > 0, "The distance must be at least 1");

        this.data = data_;
        this.interval = sample_size;
    }

    /***************************************************************************

        Construct an instance and allocate memory

        This takes a `count` of pre-image and a sample size, or distance.
        For example, if one wishes to represent a range of 1000 pre-images with
        this cache, and perform no more than 5 hash operations each time,
        the `sample_size` should be `5` and the `count` should be `200`
        (1000 / 5).

        Params:
          count = Number of samples to store (number of entries in the array)
          sample_size = Distance between two pre-images. If the value 1 is
                        provided, the pre-images will be consecutives and
                        this struct will behave essentially like an array.

    ***************************************************************************/

    public this (ulong count, ulong sample_size) pure
    {
        assert(count > 1, "A count of less than 2 does not make sense");
        this(new Hash[](count), sample_size);
    }

    /***************************************************************************

        Populate this cache from the `seed`

        Params:
          seed = Initial value to derive preimage from. This will always be the
                 first value of the array.
          length = The number of entries to populate.
                   This can be used when large sample size are used,
                   and one wishes to stop initialization past a certain threshold.

    ***************************************************************************/

    public void reset (in Hash seed, size_t length)
    {
        // Set the length, so that extra entries are not accessible through
        // `opIndex`
        assert(length > 0, "The length of the array should be at least 1");
        this.data.length = length;
        () @trusted { assumeSafeAppend(this.data); }();
        this.reset(seed);
    }

    /// Ditto
    public void reset (Hash seed) @nogc
    {
        this.data[0] = seed;
        foreach (ref entry; this.data[1 .. $])
        {
            foreach (idx; 0 .. this.interval)
                seed = hashFull(seed);
            entry = seed;
        }
    }

    /***************************************************************************

        Get the hash at index `idx` in the cycle

        Will perform at most `cycle_length % interval` computations.

    ***************************************************************************/

    public Hash opIndex (size_t index) const @nogc
    {
        immutable startIndex = (index / this.interval);
        // This will trigger out of bound if needed
        // We could possibly silently allow to index arbitrarily outside the
        // array by just taking the computational hit, since indexing past the
        // end means we are generating new pre-images, but it sounds like abuse
        Hash value = this.data[startIndex];
        foreach (_; (startIndex * this.interval) .. index)
            value = hashFull(value);
        return value;
    }

    /// Alias to the underlying data, useful when dealing with multiple levels
    public const(Hash)[] byStride () const pure @nogc { return this.data; }

    /// Returns: The number of preimages this cache can represent
    public size_t length () const pure nothrow @nogc @safe
    {
        return this.interval * this.data.length;
    }

    /// Ditto
    alias opDollar = length;
}

///
unittest
{
    Hash[32] data;
    data[0] = hashFull("Hello World");
    foreach (idx, ref entry; data[1 .. $])
        entry = hashFull(data[idx]);

    // First case and last two are degenerate
    immutable intervals = [1, 2, 4, 8, 16];
    foreach (interval; intervals)
    {
        auto cache = PreImageCache(data.length / interval, interval);
        cache.reset(data[0]);
        foreach (idx, const ref value; data)
            assert(value == cache[idx]);

        // Test `length` and `$` properties
        assert(cache[$-1] == data[$-1]);
        assert(cache[cache.length - 1] == data[$-1]);

        switch (interval)
        {
        case 32:
        case 16:
        case 8:
        case 4:
        case 2:
        case 1:
            assert(cache.data.length == (32 / interval));
            size_t data_idx;
            foreach (idx, const ref entry; cache.data)
            {
                assert(entry == data[data_idx]);
                data_idx += interval;
            }
            break;

        case 64:
            assert(cache.data.length == 1);
            assert(cache.data[0] == data[0]);
            break;

        default:
            assert(0);
        }
    }
}

/*******************************************************************************

    Combines two PreImageCache, allowing for faster lookup

    Nodes generate a large amount of pre-images on startup, then will seek to
    a certain position in their pre-image chain and use the values sequentially.
    In order to reduce the space usage of nodes, while ensuring they don't
    get random delays while seeking pre-images, this struct holds two caches.
    The `seeds` are sparse values spawing the whole pre-image chain, while the
    `preimages` are consecutive values for the current cycle.

*******************************************************************************/

public struct PreImageCycle
{
    @safe nothrow:

    /// Make sure we get initialized by disabling the default ctor
    @disable public this ();

    /// The total number of pre-images
    public static immutable ulong PreImageCount = 5_040_000;

    /// Construct an instance with the provided cycle length and number of cycles
    public this (in Scalar secret, in uint cycle_length, in ulong preimage_count = PreImageCount,
        Height initial_seek = Height(0))
    {
        this.secret = secret;
        this.cycles = preimage_count / cycle_length;
        this.seeds = PreImageCache(cycles, cycle_length);
        this.preimages = PreImageCache(cycle_length, 1);
        this.seek(initial_seek);
    }

    /***************************************************************************

        Get a pre-image at the specified height.

        This routine might first need to seek to the given `height`,
        hence calls might have various latency depending if the image is
        cached or not.

        Params:
          height = Requested height

        Returns:
            Pre-image at `height`

    ***************************************************************************/

    public Hash opIndex (in Height height) @nogc
    {
        this.seek(height);
        auto offset = height % this.preimages.length();
        return this.preimages[$ - offset - 1];
    }

    ///
    private Scalar secret;

    /// The number of cycles for a bulk of pre-images
    public ulong cycles;

    /***************************************************************************

        The index of the enrollment within the current cycle

        This number is incremented every time a new Enrollment is accepted
        by the consensus protocol, and reset when `nonce` is incremented.

    ***************************************************************************/

    public uint index;

    /***************************************************************************

        Seed for all enrollments for the current cycle

        This variable is changed every time `nonce` is changed,
        and contains all the roots used to generate the `preimages` value.

    ***************************************************************************/

    public PreImageCache seeds;

    /***************************************************************************

        Currently active list of pre-images

        This variable is changed every time `index` is changed, to reflect
        the current Enrollment's pre-images.

    ***************************************************************************/

    public PreImageCache preimages;

    /***************************************************************************

        Seek to the `PreImage`s at height `height`

        This will calculate the `index` and `nonce` according to the given
        height and populate the `seed` and `preimages` if neccesary.

        This will be particularly usefull since the PreImages will now be
        consumed not by new enrollments but creation of new blocks.

        Params:
          secret = The secret key of the node, used as part of the hash
                   to generate the cycle seeds
          height = Requested height

    ***************************************************************************/

    private void seek (in Height height) @nogc
    {
        import agora.utils.WellKnownPreImages;

        uint seek_index = cast (uint) (height / this.preimages.length());
        seek_index %= this.cycles;

        if (this.seeds[0] == Hash.init)
        {
            this.index = seek_index;
            const cycle_seed = hashMulti(
                this.secret, "consensus.preimages", 0);

            auto seed = getWellKnownPreImageSeed(this.secret, PreImageCycle.PreImageCount,
               this.cycles, this.index, this.seeds.interval);
            if (seed == Hash.init)
            {
                this.seeds.reset(cycle_seed);
                this.preimages.reset(this.seeds.byStride[$ - 1 - this.index]);
            }
            else
            {
                this.preimages.reset(seed);
            }

        }
        else if (seek_index != this.index)
        {
            this.index = seek_index;
            Hash seed = getWellKnownPreImageSeed(this.secret, PreImageCycle.PreImageCount,
                this.cycles, this.index, this.seeds.interval);

            if (seed == Hash.init)
               seed = this.seeds.byStride[$ - 1 - this.index];
            this.preimages.reset(seed);

        }
    }
}

version (unittest)
{
    // Test all heights of multiple cycles
    private void testPreImageCycle (uint cycle_length, ulong number_of_cycles)
    {
        import std.algorithm;
        import std.format;
        import std.range;
        import std.stdio;

        auto secret = Scalar.random();
        auto cycle = PreImageCycle(secret, cycle_length,
            number_of_cycles * cycle_length);
        ulong total_images = cycle_length * number_of_cycles;
        scope(failure) writefln("\nBatch failed with cycle %s", cycle);
        Hash[] batch;
        iota(total_images).each!( i =>
            batch ~= i == 0 ?
                hashMulti(secret, "consensus.preimages", 0)
                : hashFull(batch[i - 1]));
        batch.enumerate.each!( (idx, image) =>
            assert(cycle[Height(total_images - idx - 1)] == image));
    }
}

///
unittest
{
    const cycle_length = 2;
    const number_of_cycles = 10;
    testPreImageCycle(cycle_length, number_of_cycles);
}

///
unittest
{
    const cycle_length = 3;
    const number_of_cycles = 12;
    testPreImageCycle(cycle_length, number_of_cycles);
}

version (none)
unittest
{
    import std.stdio;
    import std.format;
    import agora.utils.WellKnownKeys;

    Scalar[string] secret_map = [
        "NODE2": NODE2.secret,
        "NODE3": NODE3.secret,
        "NODE4": NODE4.secret,
        "NODE5": NODE5.secret,
        "NODE6": NODE6.secret,
        "NODE7": NODE7.secret,
    ];

    const CycleLength = 10000;
    foreach (ref const(string) name, ref Scalar secret; secret_map)
    {
        debug auto seeds_cache = PreImageCache(PreImageCycle.PreImageCount / CycleLength,
            CycleLength);
        const cycle_seed = hashMulti(secret, "consensus.preimages", 0);
        seeds_cache.reset(cycle_seed);
        // auto first_preimage = cycle[Height(0)];
        // debug writeln("first_preimage: ", first_preimage);
        // debug writeln("seeds.data.length: ", cycle2.seeds.data.length);

        writeln(format!"static immutable Hash[] %s_PreImage_Seeds = ["(name));
        foreach (ref Hash seed; seeds_cache.data)
        {
            writeln("\tHash(`", seed, "`),");
        }
        writeln("];\n");
    }
}
