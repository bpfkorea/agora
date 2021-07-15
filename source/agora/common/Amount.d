/*******************************************************************************

   Defines a monetary type used in the blockchain

   This struct can hold an amount between 0 and 4_948_159_353 * 10^7,
   as there is an absolute maximum supply of 4_948_159_353 coins and
   each coin can be divided in up to 10^7 units.

   This struct does not expose operation overloading on purpose.
   Having operator overloading would mean that any error should be reported
   as either an `assert` being triggered or an `Exception` being thrown.
   The convenience of using `a + b` would likely mean some places wouldn't
   be properly bound checked, which would in turn open a DoS.
   Instead, we provide two kind of functions for operations:
   `bool OPNAME(ref Amount res, Type)` and `Amount mustOPNAME(Type)`

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.common.Amount;

/// Defines a monetary type used in the blockchain
public struct Amount
{
    import core.checkedint;

    /// Number of units ('cents') per coins
    public static immutable Amount UnitPerCoin   = Amount(10_000_000, true);
    /// Maximum number of BOA coins that can ever be in circulation
    public static immutable ulong  MaxCoinSupply = 4_948_159_353;
    /// Maximum amount of money that can ever be in circulation
    public static immutable Amount MaxUnitSupply =
        Amount(UnitPerCoin.value * MaxCoinSupply, true);
    /// Exact amount that needs to be staked to make a freezing transaction
    public static immutable Amount MinFreezeAmount =
        Amount(UnitPerCoin.value * 40_000, true);

    /// Helper type for `toString`
    private alias SinkT = void delegate(scope const(char)[] v) @safe;

    /// Internal data storage
    private ulong value;

    /***************************************************************************

        Construct an instance of an `Amount`

        Params:
            units = The monetary amount this new instance represent.
                    The unit is the smaller unit of currency (see `UnitPerCoin`)

    ***************************************************************************/

    public this (ulong units) nothrow pure @nogc @safe
    {
        assert(Amount.isInRange(units));
        this.value = units;
    }

    /// Copy constructor
    public this (in Amount other) nothrow pure @nogc @safe
    {
        assert(Amount.isInRange(other.value));
        this.value = other.value;
    }

    /// Pretty-print this value
    public void toString (scope SinkT dg) const @safe
    {
        import std.format;
        formattedWrite(dg, "%d", this.value);
    }

    /// Also support for Vibe.d serialization to JSON
    public string toString () const @safe
    {
        string ret;
        scope SinkT dg = (scope v) { ret ~= v; };
        this.toString(dg);
        return ret;
    }

    /// Non-throwing version of toString
    /// Use it only for debugging when called from nothrow function
    public string toStringNT () const @safe nothrow
    {
        try return this.toString();
        catch (Exception e) {return "Exception happened when calling Amount.toStringNT()";}
    }

    /// Support for Vibe.d deserialization
    public static Amount fromString (scope const(char)[] str) pure @safe
    {
        import std.conv : to;
        immutable ul = str.to!ulong;
        if (!Amount.isInRange(ul))
            throw new Exception("Invalid input value to Amount");
        return Amount(ul, true);
    }

    nothrow pure @nogc @safe:

    /***************************************************************************

        Returns:
            `true` if `value` is in the range `[0; Amount.MaxUnitSupply]`
            and can be safely used to make an `Amount`

    ***************************************************************************/

    pragma(inline, true)
    public static bool isInRange (ulong value)
    {
        return value <= MaxUnitSupply.value;
    }

    /***************************************************************************

        Returns:
            Greatest common divisor of `Amount`s in `ams`

    ***************************************************************************/

    pragma(inline, true)
    public static Amount gcd (in Amount[] ams)
    {
        import std.numeric : gcd;
        assert(ams.length != 0);
        ulong res = ams[0].value;
        foreach (idx; 1..ams.length)
            res = gcd(res, ams[idx].value);
        return Amount(res);
    }

    /// `isInRange` but as member function
    pragma(inline, true)
    public bool isValid () const
    {
        return isInRange(this.value);
    }

    /***************************************************************************

        Add another value to `this` `Amount`

        Params:
            other = Another `Amount` value. If the value is invalid,
                    `false` will be returned.
        Returns:
            `true` if the addition returned a number within bounds.
            `false` if the number is out of the [0; MaxUnitSupply] bound.

    ***************************************************************************/

    pragma(inline, true)
    public bool add (in Amount other)
    {
        bool overflow;
        this.value = addu(this.value, other.value, overflow);
        if (overflow || !this.isValid())
        {
            // If we overflow, make sure to poison the return value
            this.value = ulong.max;
            return false;
        }
        return true;
    }

    /***************************************************************************

        Multiply this `Amount` by `multiplier`

        Params:
            multiplier = Multiplier

        Returns:
            `true` if the addition returned a number within bounds.
            `false` if the number is out of the [0; MaxUnitSupply] bound.

    ***************************************************************************/

    pragma(inline, true)
    public bool mul (ulong multiplier)
    {
        bool overflow;
        this.value = mulu(this.value, multiplier, overflow);
        if (overflow || !this.isValid())
        {
            // If we overflow, make sure to poison the return value
            this.value = ulong.max;
            return false;
        }
        return true;
    }

    /***************************************************************************

        Substract another value from `this` `Amount`

        Params:
            other = Another `Amount` value. If the value is invalid,
                    `false` will be returned.
        Returns:
            `true` if the addition returned a number within bounds.
            `false` if the number is out of the [0; MaxUnitSupply] bound.

    ***************************************************************************/

    pragma(inline, true)
    public bool sub (in Amount other)
    {
        // Check for validity before calling `addu`,
        // because the value could be invalid and the substraction
        // would make it valid - but `underflow` is sticky
        bool underflow = !this.isValid();
        this.value = subu(this.value, other.value, underflow);
        if (underflow || !this.isValid())
        {
            // If we underflow, make sure to poison the return value
            this.value = ulong.max;
            return false;
        }
        return true;
    }

    /***************************************************************************

        Divide this `Amount` into `denominator` equal parts and
        returns the remainder

        This function allows to losslessly partition an `Amount`.
        Usage example include distributing an `Amount` evenly among participant,
        or computing an absolute majority of 2/3rd.

        Params:
            denominator = The value to divide by.
                          Dividing by `0` is the same as dividing by `1`.

        Returns:
            The remainder of the division

    ***************************************************************************/

    pragma(inline, true)
    public Amount div (ulong denominator)
    {
        // No-op
        if (denominator < 2) return Amount(0);

        const Amount remainder = this.value % denominator;
        this.value = (this.value / denominator);
        return remainder;
    }

    /***************************************************************************

        Take a percentage of the `value`

        Params:
            pct = Requested percentage

    ***************************************************************************/

    pragma(inline, true)
    public bool percentage (ushort pct)
    {
        bool overflow;
        this.value = mulu(this.value, pct, overflow);
        // deliberately not checking using isValid(), because after the divsion by 100,
        // the value can become valid
        if (overflow)
            return false;
        this.value /= 100;
        return this.isValid();
    }

    /***************************************************************************

        Take a percentage of the `value` and assert if the result is invalid

        Params:
            pct = Requested percentage

    ***************************************************************************/

    pragma(inline, true)
    public Amount mustPercentage (ushort pct)
    {
        this.percentage(pct) || assert(0);
        return this;
    }

    /***************************************************************************

        Count how many `other` can be paid by `this`

        Params:
            other = Another `Amount` value.

        Returns: result of integer division op (this.value / other.value)

    ***************************************************************************/

    pragma(inline, true)
    public ulong count (in Amount other)
    {
        assert(other.value > 0);
        return this.value / other.value;
    }

    /***************************************************************************

        Calculate how much proportional fee should be paid for `this`
        with the given `proportional_fee`

        Params:
            proportional_fee = fee per BOA

    ***************************************************************************/

    pragma(inline, true)
    public Amount proportionalFee (Amount proportional_fee)
    {
        Amount fee = this;
        if (fee.mul(proportional_fee.value))
            fee.div(Amount.UnitPerCoin.value);
        return fee;
    }

    /// Returns: The integral part of the amount (value / 1 BOA)
    public ulong integral () const
    {
        return this.value / UnitPerCoin.value;
    }

    /// Returns: The decimal part of the amount (value % 1 BOA)
    public ulong decimal () const
    {
        return this.value % UnitPerCoin.value;
    }

    /// Convenience version of `add` which asserts in case of overflow
    /// Prefer using this only in `unittest`s
    public ref Amount mustAdd (in Amount other) return
    {
        this.add(other) || assert(0);
        return this;
    }

    /// Convenience version of `sub` which asserts in case of underflow
    /// Prefer using this only in `unittest`s
    public ref Amount mustSub (in Amount other) return
    {
        this.sub(other) || assert(0);
        return this;
    }

    /// Support for comparison
    pragma(inline, true)
    public int opCmp (in Amount other) const pure nothrow @nogc
    {
        return this.value < other.value ? -1 : (this.value > other.value ? 1 : 0);
    }

    /// Make a value without checking bounds
    /// Used to initialize the bounds themselves, and to make invalid values
    /// in unittests
    private this (ulong units, bool dummy) { this.value = units; }
    /// Ditto
    version (unittest)
    public static Amount invalid (ulong units) { return Amount(units, true); }
}

/*******************************************************************************

        Make an Amount with the number of coins

        Params:
            num_coins = the number of coins

        Returns:
            The Amount calculated with cents per unit and the number of coins

*******************************************************************************/

public Amount coins (in ulong num_coins) @safe pure nothrow @nogc
{
    return Amount(Amount.UnitPerCoin.value * num_coins, true);
}

unittest
{
    auto am1 = 10_000.coins;
    auto am2 = Amount(100_000_000_000L);
    assert(am1 == am2);
}

///
nothrow pure @nogc @safe unittest
{
    // Typical use case is to do `if (!op) error_handling;`
    Amount two = Amount.UnitPerCoin;
    assert(two.add(two));
    assert(two.sub(two));

    // The value is still valid
    assert(two.isValid());

    // This should error
    assert(!two.sub(Amount(1)));

    // The value was poisoned
    assert(!two.isValid());
    // Even substracting it to itself (which should yield 0) doesn't work
    assert(!two.sub(two));
    // But can be reset to a sane value if needed
    two = Amount(1);
    assert(two.sub(Amount(1)));

    // mustAdd / mustSub coverage
    two.mustAdd(Amount(1));
    assert(two == Amount(1));
    two.mustSub(Amount(1));
    assert(two == Amount(0));

    // Tests for division with remainder
    Amount val = Amount.MinFreezeAmount;
    assert(val.div(3) == Amount(1));
    assert(val.integral() == 13_333);
    assert(val.decimal() == 3_333_333);

    assert(val.div(100) == Amount(33));
    assert(val.integral() == 133);
    assert(val.decimal() == 3_333_333);

    // Division without remainder
    val = Amount.MinFreezeAmount;
    assert(val.div(1000) == Amount(0));
    assert(val.integral() == 40);
    assert(val.decimal() == 0);

    // Division edge cases
    val = Amount.UnitPerCoin;
    assert(val.div(0) == Amount(0));
    assert(val == Amount.UnitPerCoin);
    assert(val.div(0) == Amount(0));
    assert(val == Amount.UnitPerCoin);
}

pure @safe unittest
{
    import std.exception;
    assert(Amount.fromString(`49481593530000000`) == Amount.MaxUnitSupply);
    assertThrown!Exception(Amount.fromString(`49481593530000001`));
    Amount maxv = Amount.MaxUnitSupply;
    assert(maxv.isValid());
    assert(!maxv.add(Amount(1)));
    assert(!maxv.isValid());
}

pure @safe nothrow @nogc unittest
{
    assert(Amount.UnitPerCoin.integral() == 1);
    assert(Amount.UnitPerCoin.decimal() == 0);

    assert(Amount.MaxUnitSupply.integral() == 4_948_159_353);
    assert(Amount.MaxUnitSupply.decimal() == 0);

    assert(Amount(500).integral() == 0);
    assert(Amount(500).decimal() == 500);

    assert(Amount(100_500_000).integral() == 10);
    assert(Amount(100_500_000).decimal() == 500_000);

    assert(Amount.MinFreezeAmount.decimal() == 0);
    assert(Amount.MinFreezeAmount.integral() == 40_000);
}

unittest
{
    import agora.serialization.Serializer;

    testSymmetry!Amount();
    // FIXME: Deserializer does not yet support deserializing immutable values
    Amount mutable = Amount.UnitPerCoin;
    testSymmetry(mutable);
}

/// comparisons
pure nothrow unittest
{
    assert(Amount(100) > Amount(99));
    assert(Amount(99) < Amount(100));
    assert(Amount(100) >= Amount(100));
    assert(!(Amount(100) > Amount(100)));

    const am1 = Amount(99);
    const am2 = Amount(100);
    assert(am1 < am2);  // const

    import std.algorithm;  // array
    auto arr = [Amount(300), Amount(100), Amount(100), Amount(200)];
    arr.sort!((a, b) => a > b);
    assert(arr == [Amount(300), Amount(200), Amount(100), Amount(100)]);

    arr.sort!((a, b) => a < b);
    assert(arr == [Amount(100), Amount(100), Amount(200), Amount(300)]);
}

unittest
{
    assert(Amount(100) == Amount.gcd([Amount(100), Amount(100), Amount(200),
        Amount(300)]));
    assert(Amount(1) == Amount.gcd([Amount(3), Amount(5), Amount(7),
        Amount(13)]));
    assert(Amount(3) == Amount.gcd([Amount(3)]));
}

unittest
{
    Amount amt = Amount(100);
    bool is_valid = amt.percentage(33);
    assert(amt == Amount(33));
    assert(is_valid);

    is_valid = amt.percentage(33);
    assert(amt == Amount(10));
    assert(is_valid);

    is_valid = amt.percentage(10);
    assert(amt == Amount(1));
    assert(is_valid);

    amt = Amount.MaxUnitSupply;
    assert(amt.percentage(100));
    assert(!amt.percentage(101));
}

unittest
{
    Amount amt = Amount(100);
    assert(amt.mul(44));
    assert(amt == Amount(4400));
    assert(!amt.mul(ulong.max));
}

unittest
{
    Amount coin = Amount.UnitPerCoin;
    assert(coin.proportionalFee(Amount(44)) == Amount(44));
    coin.div(2);
    assert(coin.proportionalFee(Amount(44)) == Amount(22));
    assert(!coin.proportionalFee(Amount.MaxUnitSupply).isValid());
}
