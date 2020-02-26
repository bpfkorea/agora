/*******************************************************************************

    Function definition and helper related to serialization

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.common.Serializer;

import agora.common.Types;
import std.range.primitives;

///
unittest
{
    import agora.common.Amount;
    static struct Foo
    {
        ubyte a;
        ushort b;
        uint c;
        ulong d;
        Amount e;
        ubyte[] f;
        long g;
        string h;
    }
    const Foo f = Foo(1, ushort.max, uint.max, ulong.max, Amount(100), [1, 2, 3],
        42, "69");
    assert(serializeFull(f) == [
        1,                       // ubyte(1)     == 1 byte
        253,255, 255,            // ushort.max   == 3 bytes
        254, 255, 255, 255, 255, // uint.max     == 5 bytes
        255, 255, 255, 255, 255, 255, 255, 255, 255, // ulong.max == 9bytes
        100,                     // Amount(100)  == 1 byte
        3, 1, 2, 3,              // ubyte[1,2,3] == 4 bytes
        42, 0, 0, 0, 0, 0, 0, 0, // long         == 8 bytes
        2, 54, 57]);             // string       == 1 byte length + 2 char bytes
}

/// Type of delegate SerializeDg
public alias SerializeDg = void delegate(scope const(ubyte)[]) @safe;

/// Traits to check if a given type has a custom serialization behavior
private enum hasSerializeMethod (T) = is(T == struct)
    && is(typeof(T.init.serialize(SerializeDg.init)));

/*******************************************************************************

    Serialize a type and returns it as an `ubyte[]`.

    Params:
        T       = Top level type of data
        record  = Data to serialize
        dg      = Serialization delegate (equivalent to an output range)
        compact = Whether integers are serialized in variable-length form

    Returns:
        The serialized `ubyte[]`

*******************************************************************************/

public ubyte[] serializeFull (T) (scope const auto ref T record)
    @safe
{
    ubyte[] res;
    scope SerializeDg dg = (scope const(ubyte[]) data) @safe
    {
        res ~= data;
    };
    serializePart(record, dg);
    return res;
}

/// Ditto
public void serializePart (T) (scope const auto ref T record, scope SerializeDg dg)
    if (!hasSerializeMethod!T && isInputRange!T && hasLength!T)
{
    serializePart(record.length, dg);
    foreach (ref v; record)
        serializePart(v, dg);
}

///
unittest
{
    static struct Foo
    {
        const(ubyte)[] bar;
    }

    const(Foo)[] arr = [
        { bar: [ 6, 5, 4,  3, 2, 1, 0 ], },
        { bar: [ 9, 8, 7,  0], },
        { bar: [ 4, 4, 4,  4], },
        { bar: [ 2, 4, 8, 16], },
        { bar: [ 0, 1, 2,  4], },
    ];
    immutable ubyte[] result = [
        5,                   // arr.length
        7,                   // arr[0].bar.length
        6, 5, 4, 3, 2, 1, 0, // arr[0].bar
        4,                   // arr[1].bar.length
        9, 8, 7, 0,          // arr[1].bar
        4,                   // arr[2].bar.length
        4, 4, 4, 4,          // arr[2].bar
        4,                   // arr[3].bar.length
        2, 4, 8, 16,         // arr[3].bar
        4,                   // arr[4].bar.length
        0, 1, 2, 4,          // arr[4].bar
    ];

    assert(arr.serializeFull() == result);
}

/// Ditto
public void serializePart (T) (scope const auto ref T record, scope SerializeDg dg)
    @safe
    if (is(T == struct))
{
    import geod24.bitblob;

    static if (hasSerializeMethod!T)
        record.serialize(dg);
    // BitBlob are fixed size and thus, value types
    // If we use an `ubyte[]` overload, the length gets serialized
    else static if (is(T : BitBlob!N, size_t N))
        dg(record[]);
    else
        foreach (const ref field; record.tupleof)
            serializePart(field, dg);
}

/// Ditto
public void serializePart (ubyte record, scope SerializeDg dg)
    @trusted
{
    dg((cast(ubyte*)&record)[0 .. ubyte.sizeof]);
}

/// Ditto
public void serializePart (ushort record, scope SerializeDg dg)
    @trusted
{
    toVarInt(record, dg);
}

/// Ditto
public void serializePart (uint record, scope SerializeDg dg)
    @trusted
{
    toVarInt(record, dg);
}

/// Ditto
public void serializePart (long record, scope SerializeDg dg)
    @trusted
{
    dg((cast(ubyte*)&record)[0 .. long.sizeof]);
}

/// Ditto
public void serializePart (ulong record, scope SerializeDg dg, CompactMode compact = CompactMode.Yes)
    @trusted
{
    if (compact == CompactMode.Yes)
        toVarInt(record, dg);
    else
        dg((cast(ubyte*)&record)[0 .. ulong.sizeof]);
}

/// Ditto
public void serializePart (scope cstring record, scope SerializeDg dg)
    @trusted
{
    serializePart(record.length, dg);
    dg(cast(const ubyte[])record);
}

/// Ditto
public void serializePart (scope const(ubyte)[] record, scope SerializeDg dg)
    @safe
{
    serializePart(record.length, dg);
    dg(record);
}

/// Ditto
public void serializePart (scope const(Hash)[] record, scope SerializeDg dg)
    @trusted
{
    serializePart(record.length, dg);
    foreach (hash; record)
        serializePart(hash, dg);
}

/*******************************************************************************

    Unsigned Integers to Serialized variable length integer
    and return it as a ubyte[].

    VarInt Size
    size <= 0xFC(252)  -- 1 byte   ubyte
    size <= USHORT_MAX -- 3 bytes  (0xFD + ushort)
    size <= UINT_MAX   -- 5 bytes  (0xFE + uint)
    size <= ULONG_MAX  -- 9 bytes  (0xFF + ulong)

    Params:
        T = Type of unsigned integer to serialize
        var = Instance of `T` to serialize
        dg  = Serialization delegate
    Returns:
        The serialized convert variable length integer

*******************************************************************************/

private void toVarInt (T) (const T var, scope SerializeDg dg)
    @trusted
    if (is(T == ushort) || is(T == uint) || is(T == ulong))
{
    assert(var >= 0);
    static immutable ubyte[] type = [0xFD, 0xFE, 0xFF];
    if (var <= 0xFC)
        dg((cast(ubyte*)&(*cast(ubyte*)&var))[0 .. 1]);
    else if (var <= ushort.max)
    {
        dg(type[0..1]);
        dg((cast(ubyte*)&(*cast(ushort*)&var))[0 .. ushort.sizeof]);
    }
    else if (var <= uint.max)
    {
        dg(type[1..2]);
        dg((cast(ubyte*)&(*cast(uint*)&var))[0 .. uint.sizeof]);
    }
    else if (var <= ulong.max)
    {
        dg(type[2..3]);
        dg((cast(ubyte*)&(*cast(ulong*)&var))[0 .. ulong.sizeof]);
    }
    else
        assert(0);
}

/// For varint
unittest
{
    ubyte[] res;
    scope SerializeDg dg = (scope const(ubyte[]) data)
    {
        res ~= data;
    };
    toVarInt(ulong.init, dg);
    assert(res == [0x00]);
    res.length = 0;
    toVarInt(252uL, dg);
    assert(res == [0xFC]);
    res.length = 0;
    toVarInt(253uL, dg);
    assert(res == [0xFD, 0xFD, 0x00]);
    res.length = 0;
    toVarInt(255uL, dg);
    assert(res == [0xFD, 0xFF, 0x00]);
    res.length = 0;
    toVarInt(ushort.max, dg);
    assert(res == [0xFD, 0xFF, 0xFF]);
    res.length = 0;
    toVarInt(0x10000u, dg);
    assert(res == [0xFE, 0x00, 0x00, 0x01, 0x00]);
    res.length = 0;
    toVarInt(uint.max, dg);
    assert(res == [0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
    res.length = 0;
    toVarInt(0x100000000u, dg);
    assert(res == [0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    res.length = 0;
    toVarInt(ulong.max, dg);
    assert(res == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
}

/// endianess tests
unittest
{
    static struct S
    {
        uint[] arr = [0, 1, 2];
    }

    S s;  // always serialized in little-endian format
    assert(s.serializeFull == [3, 0, 1, 2, ]);
}

/// BitBlob tests
unittest
{
    Hash /* BitBlob!512 */ val;
    ubyte[] serialized = val.serializeFull();
    assert(serialized.length == 64);
    assert(serialized == (ubyte[64]).init);
}
