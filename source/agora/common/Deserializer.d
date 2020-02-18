/*******************************************************************************

    Function definition and helper related to Deserialization

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.common.Deserializer;

import agora.common.Types;
import agora.common.crypto.Key;

import std.algorithm;
import std.range;
import std.traits;

/// test various serialization / deserialization of types
unittest
{
    import agora.consensus.data.Block;
    import agora.common.Hash;
    import agora.common.Serializer;
    import agora.consensus.data.Transaction;
    import agora.consensus.Genesis;

    ubyte[] block_bytes = serializeFull(GenesisBlock);
    assert(deserializeFull!(const(Block))(block_bytes) == GenesisBlock);

    // Check that there is no trailing data
    ubyte[] blocks_data = serializeFull(GenesisBlock) ~ serializeFull(GenesisBlock);

    void deserializeArrayEntry () @safe
    {
        scope DeserializeDg dg = (size) @safe
        {
            scope(exit) blocks_data = blocks_data[size .. $];
            return blocks_data[0 .. size];
        };

        const newblock = deserializeFull!Block(dg);
        assert(newblock == GenesisBlock);
    }

    deserializeArrayEntry();
    deserializeArrayEntry();

    // transaction test
    auto tx_bytes = serializeFull(GenesisTransaction);
    assert(deserializeFull!Transaction(tx_bytes) == GenesisTransaction);

    // test of various field types
    static struct S
    {
        uint i;
        string s;

        void serialize (scope SerializeDg dg) const @safe
        {
            serializePart(this.i, dg);
            serializePart(this.s, dg);
        }

        void deserialize (scope DeserializeDg dg) @safe
        {
            this.i = deserializeFull!uint( dg);
            this.s = deserializeFull!string(dg);
        }
    }

    auto s = S(42, "foo");
    auto bytes = serializeFull(s);
    assert(bytes.deserializeFull!S == s);
}

/// Type of delegate deserializeDg
public alias DeserializeDg = ubyte[] delegate(size_t size) @safe;

/// Traits to check if a given type has an in place deserialization routine
private enum hasDeserializeMethod (T) = is(T == struct)
    && is(typeof(T.init.deserialize(DeserializeDg.init)));

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
        bool g;
    }
    /// See the example in `agora.common.Serializer` for the serialization part
    ubyte[] data = [
        1,                       // ubyte(1)
        253, 255, 255,           // ushort.max
        254, 255, 255, 255, 255, // uint.max
        255, 255, 255, 255, 255, 255, 255, 255, 255, // ulong.max
        100,                     // Amount(100)
        3, 1, 2, 3,              // ubyte[1,2,3]
        0,                       // bool(false)
    ];
    assert(deserializeFull!Foo(data) == Foo(1, ushort.max, uint.max, ulong.max,
        Amount(100), [1, 2, 3]));
}

/*******************************************************************************

    Deserialize a data type and return it

    Params:
        T = Type of data to deserialize
        data = Binary serialized representation of `T` to be deserialized
        dg   = Delegate to read binary data for deserialization
        compact = Whether integers are serialized in variable-length form

    Returns:
        The deserialized data type

*******************************************************************************/

public T deserializeFull (T) (scope ubyte[] data) @safe
{
    scope DeserializeDg dg = (size) @safe
    {
        ubyte[] res = data[0 .. size];
        data = data[size .. $];
        return res;
    };
    return deserializeFull!T(dg);
}

/// Ditto
public T deserializeFull (T) (
    scope DeserializeDg dg, CompactMode compact = CompactMode.Yes)
    @safe
{
    import geod24.bitblob;

    // Custom deserialization trumps everything
    static if (hasDeserializeMethod!T)
    {
        T retval = T.init;
        retval.deserialize(dg);
        return retval;
    }

    // BitBlob are fixed size and thus, value types
    // If we use an `ubyte[]` overload, the deserializer looks for the length
    else static if (is(T : BitBlob!N, size_t N))
        return T(dg(T.Width));

    // Array deserialization can be optimized in many occasions
    else static if (isNarrowString!T)
    {
        alias E = ElementEncodingType!T;
        size_t length = deserializeVarInt!size_t(dg);

        T process () @trusted
        out (record)
        {
            debug
            {
                import std.utf;
                record.validate();
            }
        }
        do { return cast(E[]) (dg(E.sizeof * length)); }
        return process().dup;
    }

    // If it's binary data, just copy it
    else static if (is(immutable(T) == immutable(ubyte[])))
    {
        size_t length = deserializeVarInt!size_t(dg);
        return dg(ubyte.sizeof * length).dup;
    }

    // Array deserialization
    else static if (is(T : E[], E))
    {
        size_t length = deserializeVarInt!size_t(dg);
        return iota(length).map!(_ => dg.deserializeFull!(ElementType!T)).array();
    }

    // Enum deserialize as their base type
    else static if (is(T == enum))
    {
        return cast(T) deserializeFull!(OriginalType!T)(dg);
    }

    // 'bool' need to be converted explicitly
    else static if (is(Unqual!T == bool))
        return !!dg(T.sizeof)[0];

    // Possibly encoding integer
    else static if (isUnsigned!T)
    {
        // `ubyte` don't need binary encoding since they are already the
        // smallest possible size
        static if (is(Unqual!T == ubyte))
            return dg(ubyte.sizeof)[0];
        else
        {
            if (compact == CompactMode.Yes)
                return deserializeVarInt!T(dg);
            else
                return () @trusted { return *cast(T*)(dg(T.sizeof).ptr); }();
        }
    }

    // Other integers / scalars
    else static if (isScalarType!T)
        return () @trusted { return *cast(T*)(dg(T.sizeof).ptr); }();

    // Default to per-field deserialization for struct
    else static if (is(T == struct))
    {
        Target convert (Target) ()
        {
            return deserializeFull!Target(dg, compact);
        }
        return T(staticMap!(convert, Fields!T));
    }

    else
        static assert(0, "Unhandled type: " ~ T.stringof);
}

/*******************************************************************************

    Deserialize an integer of variable length using Bitcoin-style encoding

    VarInt Size
    size_tag is first a ubyte
    size_tag <= 0xFC(252)  -- 1 byte   ubyte
    size_tag == 0xFD       -- 3 bytes  (0xFD + ushort)
    size_tag == 0xFE       -- 5 bytes  (0xFE + uint)
    size_tag == 0xFF       -- 9 bytes  (0xFF + ulong)

    Params:
        T = Type of unsigned integer to deserialize
        dg = source of binary data

    Returns:
      The deserialized value, typed as `T`

    Throws:
      If the deserialized value does not fit into a `T`.
      Note that for `ulong`, this function is `nothrow`.

    See_Also: https://learnmeabitcoin.com/glossary/varint

*******************************************************************************/

private T deserializeVarInt (T) (scope DeserializeDg dg)
    @safe
    if (is(Unqual!T == ushort) || is(Unqual!T == uint) || is(Unqual!T == ulong))
{
    const ubyte int_size = dg(ubyte.sizeof)[0];

    T read (InType)() @trusted
    {
        import std.exception;
        auto value = *cast(InType*)dg(InType.sizeof).ptr;
        static if (T.max < InType.max)
            enforce(value <= T.max);
        return cast(T)value;
    }

    if (int_size <= 0xFC)
        return cast(T)(int_size);
    else if (int_size == 0xFD)
        return read!ushort();
    else if (int_size == 0xFE)
        return read!uint();
    else
    {
        assert(int_size == 0xFF);
        return read!ulong();
    }
}

/// For varint
unittest
{
    ubyte[] data = [
        0x00,                           // ulong.init
        0xFC,                           // ulong(0xFC) == 1 byte
        0xFD, 0xFD, 0x00,               // ulong(0xFD) == 3 bytes
        0xFD, 0xFF, 0x00,               // ulong(0xFE) == 3 bytes
        0xFD, 0xFF, 0xFF,               // ushort.max == 3 bytes
        0xFE, 0x00, 0x00, 0x01, 0x00,   // 0x10000u   == 5 bytes
        0xFE, 0xFF, 0xFF, 0xFF, 0xFF,   // uint.max   == 5 bytes
        // 0x100000000u == 9bytes
        0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        // ulong.max == 9bytes
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    static struct Foo
    {
        ulong a;
        ulong b;
        ulong c;
        ulong d;
        ushort e;
        uint f;
        uint g;
        ulong h;
        ulong i;
    }
    assert(deserializeFull!Foo(data) == Foo(ulong.init, 252uL, 253uL, 255uL,
        ushort.max, 0x10000u, uint.max, 0x100000000u, ulong.max));
}

/// endianess tests
unittest
{
    static struct S
    {
        uint[] arr;
    }

    S s;  // always serialized in little-endian format
    assert([3, 0, 1, 2, ]
        .deserializeFull!S.arr == [0, 1, 2]);
}

/// BitBlob tests
unittest
{
    ubyte[64] serialized;
    serialized[$/2] = 0xFF;
    Hash /* BitBlob!512 */ val = deserializeFull!Hash(serialized);
    assert(val == Hash(
        `0x00000000000000000000000000000000000000000000000000000000000000FF`
        ~ `0000000000000000000000000000000000000000000000000000000000000000`));

}

// Test for invalid string
unittest
{
    import std.exception;
    import std.utf;
    ubyte[] data = [3, 167, 133, 175];
    assertThrown!UTFException(data.deserializeFull!string);
}
