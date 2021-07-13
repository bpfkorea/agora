/*******************************************************************************

    Defines method to format types to their human readable representation

    This approach allows to take the string formatting out of the type,
    simplifying the implementation and reducing dependencies.
    It is assumed that a human-readable representation will not rely on
    non-visible (`private`, `package`, `protected`) data,
    or data that cannot be accessed without mutation.

    Note:
      This module currently does not use `in` sink as Phobos does not recognize
      them when `-preview=in` is used.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.utils.PrettyPrinter;

import agora.common.Amount;
import agora.common.BitMask;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.protocol.Data;
import agora.consensus.data.Enrollment;
version (unittest) import agora.consensus.data.genesis.Test;
import agora.consensus.data.Transaction;
import agora.crypto.Key;
import agora.crypto.Schnorr: Signature;

import std.algorithm;
import std.format;
import std.range;

///
unittest
{
    import agora.utils.Log;

    void myFunction (T) (T data)
    {
        Logger log = Log.lookup(__MODULE__);
        // Supported types: Amount, Hash, Input, Output, Block, Transaction, ...
        // If a type is not supported it is returned verbatim
        log.info("Got a {} of value: {}", T.stringof, prettify(data));
    }
}

/// Returns:
/// A formatting struct for a type, or the value if no such struct exists
public auto prettify (T) (const auto ref T input) nothrow
{
    static if (is(T : const Amount))
        return AmountFmt(input);
    else static if (is(T : const Hash))
        return HashFmt(input);
    else static if (is(T : const PublicKey))
        return PubKeyFmt(input);
    else static if (is(T : const Input))
        return InputFmt(input);
    else static if (is(T : const Output))
        return OutputFmt(input);
    else static if (is(T : const Transaction))
        return TransactionFmt(input);
    else static if (is(T : const Block))
        return BlockFmt(input);
    else static if (isInputRange!T)
        return RangeFmt!T(input);
    else static if (is(T : const Enrollment))
        return EnrollmentFmt(input);
    else static if (is(T : const ConsensusData))
        return ConsensusDataFmt(input);
    else static if (is(T : const QuorumConfig))
        return QuorumConfigFmt(input);
    else static if (is(T == struct))  // recurse into fields and auto-prettify
    {
        struct Formatted
        {
            public void toString (scope void delegate (scope const char[]) @safe sink) @safe nothrow
            {
                import std.traits;
                try
                {
                    sink("{ ");
                    foreach (idx, field; FieldNameTuple!T)
                    {
                        formattedWrite(sink, "%s: %s", field,
                            prettify(__traits(getMember, input, field)));
                        if (idx + 1 < FieldNameTuple!T.length)
                            sink(", ");
                    }
                    sink(" }");
                }
                catch (Exception ex)
                {
                    assert(0, ex.msg);
                }
            }
        }

        return Formatted();
    }
    else
        return input;
}

unittest
{
    static struct S
    {
        static struct Nested
        {
            Hash hash;
            Amount amount;
        }

        static struct A
        {
            int x;
        }

        Nested nested;
        PublicKey pubkey;
        A a = A(32);
        A b = A(64);
    }

    static immutable Hash SomeHash =
        "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        ~ "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    assert(format("%s", prettify(S(S.Nested(SomeHash, Amount(1))))) ==
        "{ nested: { hash: 0x0000...e26f, amount: 0.0,000,001 }, pubkey: boa1xqqqqqqq...jq8m, a: { x: 32 }, b: { x: 64 } }");
}

/// Formatting struct for `Amount`
private struct AmountFmt
{
    private Amount value;

    public void toString (scope void delegate (scope const char[]) @safe sink) @safe nothrow
    {
        try
        {
            formattedWrite(sink, "%,d", this.value.integral());
            if (auto dec = this.value.decimal())
            {
                sink(".");
                size_t mask = 1_000_000;
                while (dec)
                {
                    if (mask == 100_000 || mask == 100)
                        sink(",");
                    sink("0123456789"[dec / mask .. (dec / mask) + 1]);
                    dec %= mask;
                    mask /= 10;
                }
            }
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

@safe unittest
{
    immutable one = Amount(1);
    assert(format("%s", AmountFmt(Amount.MaxUnitSupply)) == "500,000,000");
    assert(format("%s", AmountFmt(one)) == "0.0,000,001", format("%s", AmountFmt(one)));
    assert(format("%s", AmountFmt(Amount.UnitPerCoin)) == "1");
    assert(format("%s", AmountFmt(Amount(50_000))) == "0.0,05");
}

/// Formatting struct for `Hash` and `Signature`
private struct HashFmt
{
    private const(Hash) value;

    public void toString (scope void delegate (scope const char[]) @safe sink) @safe nothrow
    {
        try
        {
            // Only format `0xABCD..EFGH`
            enum StartUntil = 6;
            enum EndFrom    = Hash.StringBufferSize - 4;
            size_t count;
            scope void delegate (scope const char[]) @safe wrapper = (scope const data) @safe {
                    if (count < StartUntil)
                    {
                        sink(data);
                        if (count + data.length >= StartUntil)
                            sink("...");
                    }
                    if (count >= EndFrom)
                        sink(data);
                    count += data.length;
                };
            this.value.toString(wrapper);
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

@safe unittest
{
    static immutable Hash SomeHash =
        "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        ~ "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    assert(format("%s", HashFmt(SomeHash)) == "0x0000...e26f");
}

/// Formatting struct for `PublicKey`
private struct PubKeyFmt
{
    private const(PublicKey) value;

    public void toString (scope void delegate (scope const char[]) @safe sink) @safe nothrow
    {
        try
        {
            // Public keys are 63 characters, only take the first 12 and last 4
            // Only format `boa1acdefghi..6789`
            enum StartUntil = 12;
            enum EndFrom = 4;
            scope void delegate (scope const char[]) @safe wrapper = (scope const data) @safe {
                if (data.length <= StartUntil + EndFrom)
                {
                    sink(data);
                }
                else
                {
                    sink(data[0 .. StartUntil]);
                    sink("...");
                    sink(data[$ - EndFrom .. $]);
                }
            };
            this.value.toString(wrapper);
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

@safe unittest
{
    PublicKey pubkey;
    immutable expected = format("%s", PubKeyFmt(pubkey));
    assert(expected == "boa1xqqqqqqq...jq8m", "Expected: " ~ expected);
}

/// Formatting struct for `Input`
private struct InputFmt
{
    private const(Input) value;

    public this (ref const Input r) @safe nothrow
    {
        this.value = r;
    }

    public void toString (scope void delegate (scope const char[]) @safe sink) @safe nothrow
    {
        try
        {
            // todo: use better formatting for byte arrays
            import agora.crypto.Hash;
            formattedWrite(sink, "%s:%s",
                HashFmt(this.value.utxo),
                HashFmt(hashFull(this.value.unlock)));
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

@safe unittest
{
    Input input;
    assert(format("%s", InputFmt(input)) == "0x0000...0000:0x4b6e...a32f",
        format("%s", InputFmt(input)));
}

/// Formatting struct for `Output`
private struct OutputFmt
{
    private const(Output) value;

    public this (ref const Output r) @safe nothrow
    {
        this.value = r;
    }

    public void toString (scope void delegate (scope const char[]) @safe sink) @safe nothrow
    {
        try
        {
            formattedWrite(sink, "%s(%s)<%s>",
                PubKeyFmt(this.value.address), AmountFmt(this.value.value), this.value.type);
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

@safe unittest
{
    Output output;
    assert(format("%s", OutputFmt(output)) == "boa1xqqqqqqq...jq8m(0)<Payment>");
}

/// Format a whole transaction
private struct TransactionFmt
{
    private const(Transaction) value;

    public this (ref const Transaction r) @safe nothrow
    {
        this.value = r;
    }

    public void toString (scope void delegate (scope const char[]) @safe sink)
        @safe nothrow
    {
        try
        {
            enum InputPerLine = 3;
            enum OutputPerLine = 3;

            if (this.value.inputs.length)
                formattedWrite(sink, "Inputs (%d):%s%(%(%s, %),\n%)\n",
                    this.value.inputs.length,
                    this.value.inputs.length > InputPerLine ? "\n" : " ",
                    this.value.inputs.map!(v => InputFmt(v)).chunks(InputPerLine));
            else
                formattedWrite(sink, "Inputs: None\n");

            formattedWrite(sink, "Outputs (%d):%s%(%(%s, %),\n%)",
                this.value.outputs.length,
                this.value.outputs.length > OutputPerLine ? "\n" : " ",
                this.value.outputs.map!(v => OutputFmt(v)).chunks(OutputPerLine));
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

@safe unittest
{
    static immutable ResultStr0 = `Inputs: None
Outputs (6):
boa1xzval2a3...gsh2(2,000,000)<Freeze>, boa1xzval3ah...tv9n(2,000,000)<Freeze>, boa1xzval4nv...6gfy(2,000,000)<Freeze>,
boa1xrval5rz...jkm8(2,000,000)<Freeze>, boa1xrval6hd...34l5(2,000,000)<Freeze>, boa1xrval7gw...scrh(2,000,000)<Freeze>`;
    const actual0 = format("%s", TransactionFmt(GenesisBlock.frozens.front));
    assert(ResultStr0 == actual0, actual0);

    static immutable ResultStr1 = `Inputs: None
Outputs (8):
boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>,
boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>,
boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>`;
    const actual1 = format("%s", TransactionFmt(GenesisBlock.payments.front));
    assert(ResultStr1 == actual1, actual1);
}

/// Format a block header
private struct BlockHeaderFmt
{
    private const(BlockHeader) value;

    public this (ref const BlockHeader r) @safe nothrow
    {
        this.value = r;
    }

    public void toString (scope void delegate (scope const char[]) @safe sink) nothrow
        @safe
    {
        try
        {
            formattedWrite(sink, "Height: %d, Prev: %s, Root: %s, Enrollments: [%s]\nSignature: %s,\nValidators: %d/%d !(%(%s, %)),\nRandom seed: [%s],\nSlashed validators: [%s]",
                this.value.height.value, HashFmt(this.value.prev_block),
                HashFmt(this.value.merkle_root),
                this.value.enrollments.fold!((a, b) =>
                    format!"%s\n%s"(a, prettify(b)))(""),
                this.value.signature, this.value.validators.setCount, this.value.validators.count, this.value.validators.notSetIndices,
                HashFmt(this.value.random_seed),
                this.value.missing_validators.fold!((a, b) =>
                    format!"%s, %s"(a, prettify(b)))(""));
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

@safe unittest
{
    static immutable GenesisHStr = `Height: 0, Prev: 0x0000...0000, Root: 0xaf40...c93d, Enrollments: [
{ utxo: 0x210f...3b64, seed: 0xcfc5...33e1, cycles: 20, sig: 0x0183...5f8c }
{ utxo: 0x3b44...ba77, seed: 0xff4e...d698, cycles: 20, sig: 0xe3f9...9bb0 }
{ utxo: 0x7bac...ea8f, seed: 0xfb40...06ea, cycles: 20, sig: 0x375e...b319 }
{ utxo: 0x9b27...6b2c, seed: 0xe0dc...7c3e, cycles: 20, sig: 0xa72e...97c8 }
{ utxo: 0xab19...1255, seed: 0x2bd8...ee80, cycles: 20, sig: 0xe9a3...2c74 }
{ utxo: 0xdb76...2a0a, seed: 0x00eb...fb56, cycles: 20, sig: 0x07ff...88b7 }]
Signature: 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,
Validators: 0/0 !(),
Random seed: [0x0000...0000],
Slashed validators: []`;
    const actual = format("%s", BlockHeaderFmt(GenesisBlock.header));
    assert(GenesisHStr == actual, actual);
}

/// Format a whole block
private struct BlockFmt
{
    private const(Block) value;

    public this (ref const Block r) @safe nothrow
    {
        this.value = r;
    }

    public void toString (scope void delegate (scope const char[]) @safe sink)
        @safe nothrow
    {
        try
        {
            formattedWrite(sink, "%s,\nTransactions: %d\n",
                BlockHeaderFmt(this.value.header), this.value.txs.length);
            formattedWrite(sink, "%(%s\n%)", this.value.txs.map!(v => TransactionFmt(v)));
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

@safe unittest
{
    static immutable ResultStr = `Height: 0, Prev: 0x0000...0000, Root: 0xaf40...c93d, Enrollments: [
{ utxo: 0x210f...3b64, seed: 0xcfc5...33e1, cycles: 20, sig: 0x0183...5f8c }
{ utxo: 0x3b44...ba77, seed: 0xff4e...d698, cycles: 20, sig: 0xe3f9...9bb0 }
{ utxo: 0x7bac...ea8f, seed: 0xfb40...06ea, cycles: 20, sig: 0x375e...b319 }
{ utxo: 0x9b27...6b2c, seed: 0xe0dc...7c3e, cycles: 20, sig: 0xa72e...97c8 }
{ utxo: 0xab19...1255, seed: 0x2bd8...ee80, cycles: 20, sig: 0xe9a3...2c74 }
{ utxo: 0xdb76...2a0a, seed: 0x00eb...fb56, cycles: 20, sig: 0x07ff...88b7 }]
Signature: 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,
Validators: 0/0 !(),
Random seed: [0x0000...0000],
Slashed validators: [],
Transactions: 2
Inputs: None
Outputs (8):
boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>,
boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>,
boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>
Inputs: None
Outputs (6):
boa1xzval2a3...gsh2(2,000,000)<Freeze>, boa1xzval3ah...tv9n(2,000,000)<Freeze>, boa1xzval4nv...6gfy(2,000,000)<Freeze>,
boa1xrval5rz...jkm8(2,000,000)<Freeze>, boa1xrval6hd...34l5(2,000,000)<Freeze>, boa1xrval7gw...scrh(2,000,000)<Freeze>`;
    const actual = format("%s", BlockFmt(GenesisBlock));
    assert(ResultStr == actual, actual);
}

/// Format inputRange (e.g. range of blocks)
private struct RangeFmt (R)
{
    private const(R) value;

    public this (ref const R r) @safe nothrow
    {
        this.value = r;
    }

    public void toString (scope void delegate (scope const char[]) @safe sink)
        @safe nothrow
    {
        try
        {
            formattedWrite(sink, "\n====================================================\n");
            formattedWrite(sink, "%(%s\n====================================================\n%|%)",
                this.value.map!(b => prettify(b)));
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

@safe unittest
{
    static immutable ResultStr = `
====================================================
Height: 0, Prev: 0x0000...0000, Root: 0xaf40...c93d, Enrollments: [
{ utxo: 0x210f...3b64, seed: 0xcfc5...33e1, cycles: 20, sig: 0x0183...5f8c }
{ utxo: 0x3b44...ba77, seed: 0xff4e...d698, cycles: 20, sig: 0xe3f9...9bb0 }
{ utxo: 0x7bac...ea8f, seed: 0xfb40...06ea, cycles: 20, sig: 0x375e...b319 }
{ utxo: 0x9b27...6b2c, seed: 0xe0dc...7c3e, cycles: 20, sig: 0xa72e...97c8 }
{ utxo: 0xab19...1255, seed: 0x2bd8...ee80, cycles: 20, sig: 0xe9a3...2c74 }
{ utxo: 0xdb76...2a0a, seed: 0x00eb...fb56, cycles: 20, sig: 0x07ff...88b7 }]
Signature: 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,
Validators: 0/0 !(),
Random seed: [0x0000...0000],
Slashed validators: [],
Transactions: 2
Inputs: None
Outputs (8):
boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>,
boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>,
boa1xzgenes5...gm67(61,000,000)<Payment>, boa1xzgenes5...gm67(61,000,000)<Payment>
Inputs: None
Outputs (6):
boa1xzval2a3...gsh2(2,000,000)<Freeze>, boa1xzval3ah...tv9n(2,000,000)<Freeze>, boa1xzval4nv...6gfy(2,000,000)<Freeze>,
boa1xrval5rz...jkm8(2,000,000)<Freeze>, boa1xrval6hd...34l5(2,000,000)<Freeze>, boa1xrval7gw...scrh(2,000,000)<Freeze>
====================================================
Height: 1, Prev: 0x2515...9397, Root: 0xbbc4...73d7, Enrollments: []
Signature: 0x000000000000000000016f605ea9638d7bff58d2c0cc2467c18e38b36367be78000000000000000000016f605ea9638d7bff58d2c0cc2467c18e38b36367be78,
Validators: 4/6 !(1, 4),
Random seed: [0x0000...0000],
Slashed validators: [],
Transactions: 2
Inputs (1): 0x359a...f346:0x4b6e...a32f
Outputs (1): boa1xzgenes5...gm67(61,000,000)<Payment>
Inputs (1): 0xb979...d9ca:0x4b6e...a32f
Outputs (1): boa1xzgenes5...gm67(61,000,000)<Payment>
====================================================
`;
    import agora.utils.Test : genesisSpendable;
    import agora.consensus.data.Block;

    // need reproducible unlocks for test (signing generates unique nonces)
    import agora.script.Lock;
    import agora.utils.Test;
    Unlock unlocker (in Transaction, in OutputRef) @safe nothrow
    {
        return Unlock.init;
    }

    const Block second_block = makeNewBlock(GenesisBlock,
        genesisSpendable().take(2).map!(txb => txb.sign(OutputType.Payment, 0, &unlocker)), 0, Hash.init, genesis_validator_keys.length);

    auto validators = BitMask(6);
    only(0,2,3,5).each!(i => validators[i] = true);
    const signature = Signature.fromString("0x000000000000000000016f605ea9638d7bff58d2c0c" ~
                              "c2467c18e38b36367be78000000000000000000016f60" ~
                              "5ea9638d7bff58d2c0cc2467c18e38b36367be78");
    const block2 = second_block.updateSignature(signature, validators);
    const(Block)[] blocks = [GenesisBlock, block2];
    const actual = format("%s", prettify(blocks));
    assert(ResultStr == actual, actual);
}

/// Formatting struct for `Enrollment`
private struct EnrollmentFmt
{
    private const(Enrollment) enroll;

    public void toString (scope void delegate (scope const char[]) @safe sink)
        @safe nothrow
    {
        try
        {
            formattedWrite(sink, "{ utxo: %s, seed: %s, cycles: %s, sig: %s }",
                HashFmt(this.enroll.utxo_key),
                HashFmt(this.enroll.commitment),
                this.enroll.cycle_length,
                HashFmt(this.enroll.enroll_sig.toBlob()));
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}
///
unittest
{
    Hash quorumSetHash;

    Hash key = Hash("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f" ~
                    "1b60a8ce26f000000000019d6689c085ae165831e934ff763ae46a2" ~
                    "a6c172b3f1b60a8ce26f");
    Hash seed = Hash("0X4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E2CC77AB212" ~
                     "7B7AFDEDA33B4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E" ~
                     "2CC77AB2127B7AFDEDA33B");
    Signature sig = Signature.fromString("0x000000000000000000016f605ea9638d7bff58d2c0c" ~
                              "c2467c18e38b36367be78000000000000000000016f60" ~
                              "5ea9638d7bff58d2c0cc2467c18e38b36367be78");
    Enrollment enrollment =
    {
        utxo_key: key,
        commitment: seed,
        cycle_length: 1008,
        enroll_sig: sig,
    };

    static immutable Res1 = `{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }`;

    assert(Res1 == format("%s", prettify(enrollment)),
                   format("%s", prettify(enrollment)));
}

/// Formatting struct for `ConsensusData`
private struct ConsensusDataFmt
{
    private const(ConsensusData) data;

    public void toString (scope void delegate (scope const char[]) @safe sink)
        @safe nothrow
    {
        try
        {
            formattedWrite(sink, "{ tx_set: %s, enrolls: %s, missing_validators: %s, time_offset: %s }",
                this.data.tx_set.map!(tx => HashFmt(tx)),
                this.data.enrolls.map!(enroll => EnrollmentFmt(enroll)),
                this.data.missing_validators,
                this.data.time_offset);
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

///
unittest
{
    import agora.common.Set;
    import agora.crypto.Hash;
    import agora.serialization.Serializer;

    Hash quorumSetHash;

    Hash key = Hash("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f" ~
                    "1b60a8ce26f000000000019d6689c085ae165831e934ff763ae46a2" ~
                    "a6c172b3f1b60a8ce26f");
    Hash seed = Hash("0X4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E2CC77AB212" ~
                     "7B7AFDEDA33B4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E" ~
                     "2CC77AB2127B7AFDEDA33B");
    Signature sig = Signature.fromString("0x000000000000000000016f605ea9638d7bff58d2c0c" ~
                              "c2467c18e38b36367be78000000000000000000016f60" ~
                              "5ea9638d7bff58d2c0cc2467c18e38b36367be78");
    const Enrollment record =
    {
        utxo_key: key,
        commitment: seed,
        cycle_length: 1008,
        enroll_sig: sig,
    };

    const(ConsensusData) cd =
    {
        tx_set: GenesisBlock.txs.map!(tx => tx.hashFull()).array,
        enrolls: [ record, record, ],
        missing_validators: [0, 2, 4],
        time_offset: 123,
    };

    static immutable Res1 = `{ tx_set: [0x2686...31b7, 0xeb5e...4551], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }], missing_validators: [0, 2, 4], time_offset: 123 }`;

    assert(Res1 == format("%s", prettify(cd)),
                   format("%s", prettify(cd)));
}

/// Formatting struct for `QuorumConfig`
private struct QuorumConfigFmt
{
    private const(QuorumConfig) data;

    public void toString (scope void delegate (scope const char[]) @safe sink)
        @safe nothrow
    {
        try
        {
            formattedWrite(sink, "{ thresh: %s, nodes: %s, subqs: %s }",
                this.data.threshold,
                this.data.nodes.map!(node => HashFmt(node)),
                this.data.quorums.map!(subq => QuorumConfigFmt(subq)));
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

///
unittest
{
    auto quorum = immutable(QuorumConfig)(2,
        [Hash("0x11c6b0395c8e1716978c41958eab84e869755c09f7131b3bbdc882a647cb3f2c46c450607c6da71d34d1eab28fbfdf14376b444ef46ed1d0a7d2237ab430ebf5"),
         Hash("0xdfcada320948a86f6027daf7e5a964a36103ea0e662abaa692212392a280b7c211e56beb2bf83fbc53459603c6750e00cdc194c773f9941dc43b07c6f639e5fd")],
        [immutable(QuorumConfig)(3,
            [Hash("0x11c6b0395c8e1716978c41958eab84e869755c09f7131b3bbdc882a647cb3f2c46c450607c6da71d34d1eab28fbfdf14376b444ef46ed1d0a7d2237ab430ebf5"),
             Hash("0xdfcada320948a86f6027daf7e5a964a36103ea0e662abaa692212392a280b7c211e56beb2bf83fbc53459603c6750e00cdc194c773f9941dc43b07c6f639e5fd")],
            [immutable(QuorumConfig)(4,
                [Hash("0x11c6b0395c8e1716978c41958eab84e869755c09f7131b3bbdc882a647cb3f2c46c450607c6da71d34d1eab28fbfdf14376b444ef46ed1d0a7d2237ab430ebf5"),
                 Hash("0xdfcada320948a86f6027daf7e5a964a36103ea0e662abaa692212392a280b7c211e56beb2bf83fbc53459603c6750e00cdc194c773f9941dc43b07c6f639e5fd"),
                 Hash("0xdfcada320948a86f6027daf7e5a964a36103ea0e662abaa692212392a280b7c211e56beb2bf83fbc53459603c6750e00cdc194c773f9941dc43b07c6f639e5fd")])])]);

    static immutable Res1 = `{ thresh: 2, nodes: [0x11c6...ebf5, 0xdfca...e5fd], subqs: [{ thresh: 3, nodes: [0x11c6...ebf5, 0xdfca...e5fd], subqs: [{ thresh: 4, nodes: [0x11c6...ebf5, 0xdfca...e5fd, 0xdfca...e5fd], subqs: [] }] }] }`;

    assert(Res1 == format("%s", prettify(quorum)),
                   format("%s", prettify(quorum)));
}
