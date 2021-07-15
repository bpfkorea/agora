/*******************************************************************************

    Contains a simple Set implementation (wrapper around builtin hashmaps)

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.common.Set;

import agora.common.Types;
import agora.serialization.Serializer;

import libsodium.randombytes;

import std.algorithm;
import std.array;
import std.range;
import std.typecons;

import core.stdc.string;

/// simplified Set() code with some convenience methods,
/// could use a drop-in implementation later.
public struct Set (T)
{
    ///
    bool[T] _set;
    alias _set this;

    /// Put an element in the set
    public void put (T key)
    {
        this._set[key] = true;
    }

    /// Remove an element from the set
    public void remove (T key)
    {
        this._set.remove(key);
    }

    /// Support for `-checkaction=context` in LDC 1.26.0,
    /// can be removed when LDC 1.27.0 is the oldest supported release
    /// https://github.com/dlang/druntime/pull/3412
    public string toString () const
    {
        import std.format;

        return format("%(%s, %)",
                      this._set.byKeyValue.filter!(tup => tup.value)
                      .map!(tup => tup.key));
    }

    /// Walk over all elements and call dg(elem)
    private int opApplyImpl (DGT) (scope DGT dg)
    {
        foreach (key; this._set.byKey)
        {
            if (auto ret = dg(key))
                return ret;
        }

        return 0;
    }

    /// Ditto
    public int opApply (scope int delegate(T) dg)
    {
        return this.opApplyImpl(dg);
    }

    /// Ditto
    public int opApply (scope int delegate(T) @safe dg) @safe
    {
        return this.opApplyImpl(dg);
    }

    /// Ditto
    public int opApply (scope int delegate(T) nothrow dg) nothrow
    {
        return this.opApplyImpl(dg);
    }

    /// Ditto
    public int opApply (scope int delegate(T) @safe nothrow dg) @safe nothrow
    {
        return this.opApplyImpl(dg);
    }

    /// Build a new Set out of the provided range
    public static SetT from (SetT = Set, Range) (Range range)
    {
        Set map;
        foreach (T item; range)
            map.put(item);
        return map;
    }

    /// Fill an existing set with elements from an array
    public void fill (T[] rhs)
    {
        foreach (key; rhs)
            this.put(key);
    }

    /// Returns true if the set has the element e, otherwise returns false
    public auto opBinary (string op)(in T e) const nothrow pure @nogc if (op == "in")
    {
        return e in _set;
    }

    /***************************************************************************

        Serialization support

        Params:
            dg = Serialize delegate

    ***************************************************************************/

    public void serialize (scope SerializeDg dg) const @safe
    {
        serializePart(this._set.length, dg);
        foreach (const ref value; this._set.byKey)
            serializePart(value, dg);
    }

    /***************************************************************************

        Returns a newly instantiated Set of type `SetT`

        Params:
            SetT = Qualified type of Set to return
            dg   = Delegate to read binary data
            opts = Deserialization options (should be forwarded)

        Returns:
            A new instance of type `SetT`

    ***************************************************************************/

    public static SetT fromBinary (SetT) (
        scope DeserializeDg dg, in DeserializerOptions opts) @safe
    {
        size_t length = deserializeLength(dg, opts.maxLength);
        return SetT.from!(SetT)(
            iota(length).map!(_ => deserializeFull!(T)(dg, opts)));
    }

    /// Provide a range to iterate on
    public typeof(this._set.byKey) opSlice ()
    {
        return this._set.byKey;
    }
}

/// fill the buffer with the set's keys
private void fillFrom (T) (ref T[] buffer, Set!T input)
{
    buffer.length = input.length;
    assumeSafeAppend(buffer);

    size_t idx;
    foreach (address; input)
        buffer[idx++] = address;
}

/**
    Return an array of unique elements from the input set in
    a randomly distributed order.

    Params:
        T     = the element type of the set
        input = the input set
        count = the number of elements to return,
                if set to zero then input.length is implied

    Returns:
        a randomly distributed array of $count elements
*/
public T[] pickRandom (T) (Set!T input, size_t count = 0)
{
    if (count == 0)
        count = input.length;

    static T[] buffer;
    buffer.fillFrom(input);

    const expected_count = min(count, buffer.length);

    // todo: a faster method could be to swap(last_idx, new_idx)
    T[] result;
    while (result.length < expected_count)
    {
        auto idx = randombytes_uniform(cast(uint)buffer.length);
        result ~= buffer[idx];
        buffer.dropIndex(idx);
    }

    return result;
}

///
unittest
{
    auto set = Set!uint.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    auto randoms = set.pickRandom(5);
    sort(randoms);
    assert(randoms.uniq.count == 5);

    auto full = set.pickRandom();
    sort(full);
    assert(full.uniq.count == set.length);
}

/// serialization test for Set!int
unittest
{
    auto old_set = Set!uint.from([2, 4, 6, 8]);
    auto bytes = old_set.serializeFull();
    auto new_set = deserializeFull!(Set!uint)(bytes);

    assert(new_set.length == old_set.length);
    old_set.each!(value => assert(value in new_set));
}

/// serialization test for Set!string
unittest
{
    auto old_set = Set!string.from(["foo", "bar", "agora"]);
    auto bytes = old_set.serializeFull();
    auto new_set = deserializeFull!(Set!string)(bytes);

    assert(new_set.length == old_set.length);
    old_set.each!(value => assert(value in new_set));
}

/**
    Drop element at index from array and update array length.
    Note: This is extremely unsafe, it assumes there are no
    other pointers to the internal slice memory.
*/
private void dropIndex (T) (ref T[] arr, size_t index)
{
    assert(index < arr.length);
    immutable newLen = arr.length - 1;

    if (index != newLen)
        memmove(&(arr[index]), &(arr[index + 1]), T.sizeof * (newLen - index));

    arr.length = newLen;
}

///
unittest
{
    uint[] arr = [1, 2, 3];
    arr.dropIndex(1);
    assert(arr == [1, 3]);
}

unittest
{
    auto set = Set!uint.from([2, 4, 6, 8]);
    auto _2xset = set[].map!(elem => tuple(elem, 2*elem));
    _2xset.each!(tup => assert(tup[0]*2 == tup[1]));
}
