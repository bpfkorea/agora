/*******************************************************************************

    Test that `Serializer` performs NRVO correctly

    NRVO (named return value optimization) is the act of allocating space for
    a return value in the call stack of the caller, and passing a pointer
    to that memory to the callee.
    It allows to avoid copying and moving when an aggregate is returned.
    It is particularly useful when an aggregate is returned from deep down
    a stack call, when an aggregate is large, or if it has elaborate semantics
    (non-default copy constructor, postblit, destructor).

    Usually, to tell if a type is being copied or moved, one can simply
    `@disable` postblit and the copy constructor (and optionally `opAssign`).
    However, DMD uncontrollably move structs sometimes, so this is not enough.
    This module aims at testing that NRVO is actually performed by the compiler,
    since we cannot trust the frontend to tell us.

    Note that this module requires LDC >= 1.19.0.

    See_Also:
      - Discussion that started this module:
        https://forum.dlang.org/thread/miuevyfxbujwrhghmiuw@forum.dlang.org
      - Target-specific support (only return-on-stack aggregates are NRVO'd):
        https://github.com/dlang/dmd/blob/b2d6cd459aa159fa0d7cdf7a02d647e62e7b1225/src/dmd/target.d#L409-L574
        (Note: Might differ on LDC/GDC for D linkage)
      - How function define if they are able to do NRVO:
        https://github.com/dlang/dmd/blob/b2d6cd459aa159fa0d7cdf7a02d647e62e7b1225/src/dmd/func.d#L2457
      - How return statement are rewritten:
        https://github.com/dlang/dmd/blob/b2d6cd459aa159fa0d7cdf7a02d647e62e7b1225/src/dmd/func.d#L70

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.NRVO;

import agora.common.Serializer;
import agora.common.Types;
import std.stdio;

version (DigitalMars)
{
    pragma(msg, "===============================================================");
    pragma(msg, "NRVO tests disabled: One does not simply prevent moves with DMD");
    pragma(msg, "===============================================================");
}
else:

version (X86_64) {}
else static assert(0, "Only x86_64 is support at the moment, please raise an issue on Github");

/// Tiny helpers for avoiding `cast`-hell
const(void)* ptr (T) (const ref T  s) if (is(T == struct)) { return cast(const(void)*) &s; }
const(void)* ptr (T) (const ref T* s)                      { return cast(const(void)*)  s; }

/*******************************************************************************

    A struct that does side effect

    This struct can be used to make sure the ctor is only called once.
    The downside is that side effect might affect the ability to do NRVO.
    Use `check` to get a decent error message.

*******************************************************************************/

struct SideEffect (T)
{
    @disable this(this);
    @disable this(const ref SideEffect);
    @disable ref SideEffect opAssign (const ref SideEffect);

    __gshared const(T)* pointer;

    /// Overload for `deserialized`
    this (T v) @trusted nothrow @nogc
    {
        assert(pointer is null, "Pointer should be re-initialized!");
        pointer = &this.value;
    }

    /// Overload for manual test
    static if (is(typeof(T.tupleof)))
        this (typeof(T.tupleof) args) @trusted nothrow @nogc
        {
            assert(pointer is null, "Pointer should be re-initialized!");
            pointer = &this.value;
        }

    T value;

    ///
    void serialize (scope SerializeDg dg) const @safe
    {
        serializePart(this.value, dg);
    }

    ///
    public static QT fromBinary (QT) (
        scope DeserializeDg dg, const ref DeserializerOptions opts)
        @safe
    {
        return QT(deserializeFull!(typeof(QT.value))(dg, opts));
    }

    /// Check that `pointer is &this` and reset it
    public void check (string message, int line = __LINE__) const
    {
        if (ptr(pointer) !is ptr(this))
        {
            writeln("Error: ", typeof(this).stringof, " ", message, " (", line,
                    "): this=", &this, ", pointer=", pointer, ", diff=",
                    ptr(this) - ptr(pointer));
            assert(0);
        }
        pointer = null;
    }
}

///
unittest
{
    static struct S1
    {
        SideEffect!ubyte se;
        uint val;
    }

    static struct S2
    {
        S1 s1;
        ulong val;
    }

    auto inst1 = S2(S1(SideEffect!ubyte(42)));
    inst1.s1.se.check("Checking manually initialized value");

    const data = serializeFull(inst1);
    assert(data.length);
    auto inst2 = deserializeFull!S2(data);
    inst2.s1.se.check("Checking deserialized value");
}

enum Good : uint
{
    Baguette,
    Croissant,
    Choucroute,
    Chocolat,
}

struct Container (alias Struct, bool useForceNRVO = false)
{
    /** BUG LDC 1.20.1 (TODO: report):
        source/agora/test/NRVO.d(280,22): Error: struct SEContainer has constructors, cannot use { initializers }, use SEContainer( initializers ) instead
        source/agora/common/Serializer.d(624,17): Error: copy constructor agora.test.NRVO.__unittest_L199_C1.SEContainer.this(ref const(SEContainer)) is not callable using argument types (Good, SideEffect!string, SideEffect!(uint[2]), SideEffect!(ubyte[4]), SideEffect!(ulong[2]))
        source/agora/common/Serializer.d(624,17):        cannot pass rvalue argument convert() of type Good to parameter ref const(SEContainer)
        source/agora/common/Serializer.d(516,29): Error: template instance agora.common.Serializer.deserializeFull!(SEContainer) error instantiating
        source/agora/test/NRVO.d(287,43):        instantiated from here: deserializeFull!(SEContainer)
    */
    version (none)
    {
        @disable this(this);
        @disable this(const ref Container);
        @disable ref Container opAssign (const ref Container);
    }

    Good type_;
    union {
        Struct!Field1 f1;
        Struct!Field2 f2;
        Struct!Field3 f3;
        Struct!Field4 f4;
    }

    private static struct Field1 { string data; }
    private static struct Field2 { uint[2] data; }
    private static struct Field3 { ubyte[4] data; }
    private static struct Field4 { ulong[2] data; }

    /// Helper to keep calling code sane
    public void check (string message, int line = __LINE__) const
    {
        final switch (this.type_)
        {
            // Rightmost bound is exclude so we need the +1
            static foreach (Good entry; Good.min .. cast(Good)(Good.max + 1))
            {
            case entry:
                return this.tupleof[entry + 1].check(message, line);
            }
        }
    }

    void serialize (scope SerializeDg dg) const @trusted
    {
        serializePart(this.type_, dg);
    SWITCH: final switch (this.type_)
        {
            // Rightmost bound is exclude so we need the +1
            static foreach (Good entry; Good.min .. cast(Good)(Good.max + 1))
            {
            case entry:
                serializePart(this.tupleof[entry + 1], dg);
                break SWITCH;
            }
        }
    }

    static if (useForceNRVO)
    {
        static QT fromBinary (QT) (
            scope DeserializeDg dg, const ref DeserializerOptions opts)
        {
            auto type = deserializeFull!Good(dg, opts);
            final switch (type)
            {
                // Rightmost bound is exclude so we need the +1
                static foreach (Good entry; Good.min .. cast(Good)(Good.max + 1))
                {
                case entry:
                    return forceNRVO!(entry, QT)(dg, opts);
                }
            }
        }

        static QT forceNRVO (Good type, QT) (
            scope DeserializeDg dg, const ref DeserializerOptions opts)
        {
            static if (type == Good.Baguette)
                QT f = { type_: type, f1: deserializeFull!(typeof(QT.f1))(dg, opts) };
            else static if (type == Good.Croissant)
                QT f = { type_: type, f2: deserializeFull!(typeof(QT.f2))(dg, opts) };
            else static if (type == Good.Choucroute)
                QT f = { type_: type, f3: deserializeFull!(typeof(QT.f3))(dg, opts) };
            else static if (type == Good.Chocolat)
                QT f = { type_: type, f4: deserializeFull!(typeof(QT.f4))(dg, opts) };
            else
                static assert(0, "Unsupported enum value: " ~ type.stringof);
            return f;
        }
    }
    else
    {
        static QT fromBinary (QT) (
            scope DeserializeDg dg, const ref DeserializerOptions opts)
        {
            auto type = deserializeFull!Good(dg, opts);
            final switch (type)
            {
            case Good.Baguette:
                return () {
                    QT f = { type_: type, f1: deserializeFull!(typeof(QT.f1))(dg, opts) };
                    return f;
                }();
            case Good.Croissant:
                return () {
                    QT f = { type_: type, f2: deserializeFull!(typeof(QT.f2))(dg, opts) };
                    return f;
                }();
            case Good.Choucroute:
                return () {
                    QT f = { type_: type, f3: deserializeFull!(typeof(QT.f3))(dg, opts) };
                    return f;
                }();
            case Good.Chocolat:
                return () {
                    QT f = { type_: type, f4: deserializeFull!(typeof(QT.f4))(dg, opts) };
                    return f;
                }();
            }
        }
    }
}

/// Test that our approach to ensure NRVO on unions actually works
version(none) unittest
{
    /// Accept an initialized val
    static void doTest (C) (const ref C val, int line = __LINE__)
    {
        val.check("Checking constructed value", line);
        auto data = serializeFull(val);
        assert(data.length);
        scope vald = deserializeFull!C(data);
        vald.check("Checking deserialized value", line);
    }

    static void doTestWithDifferentFromBinary (bool useForceNRVO) ()
    {
        alias SRContainer = Container!(SelfRef, useForceNRVO);
        alias SEContainer = Container!(SideEffect, useForceNRVO);

        // // string
        SEContainer se1 = { Good.Baguette, f1: typeof(SEContainer.f1)("Hello World") };
        doTest(se1);
        // uint[2]
        SEContainer se2 = { Good.Croissant, f2: typeof(SEContainer.f2)([42, 420]) };
        doTest(se2);
        // ubyte[4]
        SEContainer se3 = { Good.Choucroute, f3: typeof(SEContainer.f3)([16, 32, 64, 128]) };
        doTest(se3);
        // ulong[2]
        SEContainer se4 = { Good.Chocolat, f4: typeof(SEContainer.f4)([ulong.max / 4, ulong.max / 16]) };
        doTest(se4);

        // string
        SRContainer sr1 = { Good.Baguette, f1: typeof(SRContainer.f1).T("Hello World") };
        doTest(sr1);
        // uint[2]
        SRContainer sr2 = { Good.Croissant, f2: typeof(SRContainer.f2).T([42, 420]) };
        doTest(sr2);
        // ubyte[4]
        SRContainer sr3 = { Good.Choucroute, f3: typeof(SRContainer.f3).T([16, 32, 64, 128]) };
        doTest(sr3);
        // ulong[2]
        SRContainer sr4 = { Good.Chocolat, f4: typeof(SRContainer.f4).T([ulong.max / 4, ulong.max / 16]) };
        doTest(sr4);
    }

    doTestWithDifferentFromBinary!true();

    // Suggested by https://forum.dlang.org/post/szzqmmhxjcyxmenhrxfk@forum.dlang.org
    // However it does not work:
    // Error: const(Struct!string) Checking deserialized value (346): this=700003ECCBE0, pointer=700003ECCAE8, diff=248
    version(none) doTestWithDifferentFromBinary!false();
}
