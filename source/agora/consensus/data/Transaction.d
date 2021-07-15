/*******************************************************************************

    Defines the data structure of a transaction

    A Transaction's Output contains the lock script, whereas the Input contains
    the unlock script.

    In case of simple payment transactions, the lock & unlock pairs are simple
    byte arrays containing the key and the signature.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.Transaction;

import agora.common.Amount;
import agora.common.Types;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.script.Lock;
import agora.serialization.Serializer;

import std.algorithm;
import std.array;

/*******************************************************************************

    Represents a transaction (shortened as 'tx')

    Agora uses a UTXO model for transactions, so the transaction format is
    originally derived from that of Bitcoin.

*******************************************************************************/

public struct Transaction
{
    @safe:

    /// ctor with only outputs
    public this (Output[] outputs) nothrow
    {
        outputs.sort;
        this.outputs = outputs;
    }

    /// ctor without payload
    public this (Input[] inputs, Output[] outputs,
        in Height lock_height = Height(0)) nothrow
    {
        this(outputs);
        inputs.sort;
        this.inputs = inputs;
        this.lock_height = lock_height;
    }

    /// ctor with immutable fields so the inputs and outputs must be already sorted
    public this (inout Input[] inputs, inout Output[] outputs,
        inout(ubyte)[] payload = null,
        in Height lock_height = Height(0)) inout nothrow
    {
        this.inputs = inputs;
        this.outputs = outputs;
        this.payload = payload;
        this.lock_height = lock_height;
        assert(this.inputs.dup.isStrictlyMonotonic!((a, b) => a < b));
        assert(this.outputs.dup.isSorted!((a, b) => a < b));
    }

    /// Used in some unit tests with only the lock_height set
    version (unittest)
    {
        public this (Height lock_height)
        {
            this.lock_height = Height(lock_height);
        }
    }

    /// The list of unspent `outputs` from previous transaction(s) that will be spent
    public Input[] inputs;

    /// The list of newly created outputs to put in the UTXO
    public Output[] outputs;

    /// The data to store
    public ubyte[] payload;

    /// This transaction may only be included in a block with `height >= lock_height`.
    /// Note that another tx with a lower lock time could double-spend this tx.
    public Height lock_height = Height(0);

    /// The size of the Transaction object
    public ulong sizeInBytes () const nothrow pure @nogc
    {
        ulong size = this.payload.length;
        foreach (const ref input; this.inputs)
            size += input.sizeInBytes();
        foreach (const ref output; this.outputs)
            size += output.sizeInBytes();
        return size;
    }

    /// Support for sorting transactions
    public int opCmp (in Transaction other) const nothrow @nogc
    {
        return hashFull(this).opCmp(hashFull(other));
    }

    pure nothrow @nogc:

    /// A `Freeze` transaction is one that has one or more `Freeze` outputs
    /// If there is more than one output then it is allowed to have a single
    ///  `Payment` output for a refund of any amount
    public bool isFreeze () const
    {
        return this.outputs.any!(o => o.type == OutputType.Freeze);
    }

    /// A `Coinbase` transaction is one that has one or more `Coinbase` outputs
    /// However if all outputs are not `Coinbase` then it will fail validation
    public bool isCoinbase () const
    {
        return this.outputs.any!(o => o.type == OutputType.Coinbase);
    }

    /// A `Payment` transaction is one that has outputs of type `Payment`
    public bool isPayment () const
    {
        return this.outputs.all!(o => o.type == OutputType.Payment);
    }
}

unittest
{
    import std.algorithm.sorting : isStrictlyMonotonic;
    static Transaction identity (ref Transaction tx) { return tx; }
    Transaction[] txs = [ Transaction.init, Transaction.init ];
    assert(!txs.isStrictlyMonotonic!((a, b) => identity(a) < identity(b)));
}

/// Indicates if output is frozen (staking), payment (spending) or coinbase (rewards / fees)
public enum OutputType : uint
{
    Payment,
    Freeze,
    Coinbase,
}

/*******************************************************************************

    Represents an entry in the UTXO

    This is created by a valid `Transaction` and is added to the UTXO after
    a transaction is confirmed.

*******************************************************************************/

public struct Output
{
    /// Type of output
    public OutputType type;

    /// The lock condition for this Output
    public Lock lock;

    /// The monetary value of this output, in 1/10^7
    public Amount value;

    /// The size of the Output object
    public ulong sizeInBytes () const nothrow pure @safe @nogc
    {
        return OutputType.sizeof + this.value.sizeof + this.lock.sizeInBytes();
    }

    /// Ctor
    public this (in OutputType type, inout(Lock) lock, in Amount value) inout pure nothrow @trusted
    {
        this.type = type;
        this.lock = lock;
        this.value = value;
    }

    /// Ctor
    public this (in Amount value, inout(Lock) lock, in OutputType type = OutputType.Payment) inout pure nothrow @trusted
    {
        this.type = type;
        this.lock = lock;
        this.value = value;
    }

    /// Kept here for backwards-compatibility
    public this (in Amount value, in PublicKey key, in OutputType type = OutputType.Payment) inout pure nothrow @trusted
    {
        this.type = type;
        // Bug: Used to call `genLockKey` but `-preview=in` triggers:
        // source/agora/consensus/data/Transaction.d(142,31):
        // Error: cannot implicitly convert expression genKeyLock(key) of type Lock to inout(Lock)
        // source/agora/consensus/data/genesis/Test.d(107,23):
        // called from here: Output(Amount(0LU), Lock(LockType.Key, null)).this(Amount(0LU).this(20000000000000LU), NODE2.address)
        this.lock = Lock(LockType.Key, key[].dup);
        this.value = value;
    }

    /***************************************************************************

        Kept here for backwards compatibility with tests which do not expect
        lock scripts.

        Returns:
            the public key out of the output if the lock is a `LockType.Key`,
            else returns PublicKey.init

    ***************************************************************************/

    @property public PublicKey address () const pure nothrow @safe @nogc
    {
        import agora.crypto.ECC;

        if (this.lock.type != LockType.Key)
            return PublicKey.init;

        if (this.lock.bytes.length != Point.sizeof)
            return PublicKey.init;

        Point point = Point(this.lock.bytes);
        PublicKey key = PublicKey(point[]);
        return key;
    }

    /// Support for sorting
    public int opCmp (in typeof(this) rhs) const nothrow @safe @nogc
    {
        if (this.type != rhs.type)
            return this.type < rhs.type ? -1 : 1;
        if (this.lock != rhs.lock)
            return this.lock < rhs.lock ? -1 : 1;
        return this.value.opCmp(rhs.value);
    }
}

/// The input of the transaction, which spends a previously received `Output`
public struct Input
{
    /// The hash of the UTXO to be spent
    public Hash utxo;

    /// The unlock script, which will be ran together with the matching Input's
    /// lock script in the execution engine
    public Unlock unlock;

    /// The UTXO this `Input` references must be at least `unlock_age` older
    /// than the block height at which the spending transaction wants to be
    /// included in the block. Use for implementing relative time locks.
    public uint unlock_age = 0;

    /// The size of the Input object
    public ulong sizeInBytes () const nothrow pure @safe @nogc
    {
        return this.unlock.sizeInBytes() + this.unlock_age.sizeof + this.utxo.sizeof;
    }

    /// Simple ctor
    public this (in Hash utxo_, Unlock unlock = Unlock.init, uint unlock_age = 0)
        inout pure nothrow @nogc @trusted
    {
        this.utxo = utxo_;
        this.unlock = cast(inout(Unlock))unlock; // cast: workaround for inout
        this.unlock_age = unlock_age;
    }

    /// Ctor which does hashing based on index
    public this (in Hash txhash, ulong index, uint unlock_age = 0) nothrow @safe
    {
        this.utxo = hashMulti(txhash, index);
        this.unlock_age = unlock_age;
    }

    /// Ctor which does hashing based on the `Transaction` and index
    public this (in Transaction tx, ulong index, uint unlock_age = 0) nothrow @safe
    {
        this.utxo = hashMulti(tx.hashFull(), index);
        this.unlock_age = unlock_age;
    }

    /// Ctor to create dummy inputs for Coinbase TXs
    public this (in Height height) nothrow @safe
    {
        this.utxo = hashFull(height);
    }

    /***************************************************************************

        Implements hashing support

        Params:
            dg = hashing function

    ***************************************************************************/

    public void computeHash (scope HashDg dg) const scope
        @safe pure nothrow @nogc
    {
        dg(this.utxo[]);
        hashPart(this.unlock_age, dg);
    }

    /// Support for sorting
    public int opCmp (in typeof(this) rhs) const nothrow @safe @nogc
    {
        return this.utxo.opCmp(rhs.utxo);
    }
}

/// Transaction type serialize & deserialize for unittest
unittest
{
    testSymmetry!Transaction();

    Transaction payment_tx = Transaction(
        [Input(Hash.init, 0)],
        [Output(Amount(20), Lock.init)]
    );
    testSymmetry(payment_tx);

    Transaction freeze_tx = Transaction(
        [Input(Hash.init, 0)],
        [Output(Amount(20), Lock.init, OutputType.Freeze)]
    );
    testSymmetry(freeze_tx);

    Transaction data_tx = Transaction(
        [Input(Hash.init, 0)],
        [Output.init],
        [1,2,3],
    );
    testSymmetry(data_tx);

    Transaction cb_tx = Transaction(
        [Input(Height(0))],
        [Output(Amount(20), Lock.init, OutputType.Coinbase)]);
    testSymmetry(cb_tx);
}

unittest
{
    import agora.common.Set;
    auto tx_set = Set!(const Transaction).from([Transaction.init]);
    testSymmetry(tx_set);
}

/// Transaction type hashing for unittest
unittest
{
    Transaction payment_tx = Transaction(
        [Input(Hash.init, 0)],
        [Output.init]
    );

    const tx_payment_hash = Hash(
        `0xbf16b1bb63c50170ce0e2624e13bda540c268c74a677d2d8a0571eb79cd8a3b28c408793d43e3bbee0ffd39913903c77fbd1b0cbe36b6a0b503514bbbe84b492`);
    const expected1 = payment_tx.hashFull();
    assert(expected1 == tx_payment_hash, expected1.toString());

    Transaction freeze_tx = Transaction(
        [Input(Hash.init, 0)],
        [Output(Amount(20), Lock.init, OutputType.Freeze)]
    );

    const tx_freeze_hash = Hash(
        `0x21b2cc64d38563d63a15f1d2488233e5fa6191d166a6d8f3ec570410aea99fb9273a3228bd2a2adc76df3a7daf1ee24d81a18c84a19409928579a9cd302cb7dc`);
    const expected2 = freeze_tx.hashFull();
    assert(expected2 == tx_freeze_hash, expected2.toString());
}

/*******************************************************************************

    Get sum of `Output`

    Params:
        tx = `Transaction`
        acc = Accumulator value. Pass a default-initialized value to get this
              transaction's sum of output.

    Return:
        `true` if the sum returned is correct. `false` if there was an overflow.

*******************************************************************************/

public bool getSumOutput (in Transaction tx, ref Amount acc)
    nothrow pure @safe @nogc
{
    foreach (ref o; tx.outputs)
        if (!acc.add(o.value))
            return false;
    return true;
}

unittest
{
    import vibe.data.json;
    Transaction old_tx = Transaction(
        [Input(Hash.init, 0)],
        [Output.init],
        [1,2,3],
    );
    auto json_str = old_tx.serializeToJsonString();

    Transaction new_tx = deserializeJson!Transaction(json_str);
    assert(new_tx.payload.length == old_tx.payload.length);
    assert(new_tx.payload == old_tx.payload);
}

// Check exact same Coinbase TXs for different heights generate different hashes
unittest
{
    Transaction h0_tx = Transaction(
        [Input(Height(0))],
        [Output(Amount(20), Lock.init, OutputType.Coinbase)]);

    Transaction h1_tx = Transaction(
        [Input(Height(1))],
        [Output(Amount(20), Lock.init, OutputType.Coinbase)]);

    assert(h0_tx.hashFull() != h1_tx.hashFull());
}
