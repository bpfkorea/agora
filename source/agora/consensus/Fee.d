/*******************************************************************************

    Contains the function to calculate the fees used to store the data

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.Fee;

import agora.common.Types;
import agora.common.Amount;
import agora.common.ManagedDatabase;
import agora.consensus.data.Block;
import agora.consensus.data.Transaction;
import agora.consensus.data.UTXO;
import agora.consensus.data.Params;
import agora.consensus.state.UTXOCache;
import agora.crypto.Key;

import std.math;
import std.algorithm;
import std.array;

/// Delegate to check data payload
public alias FeeChecker = string delegate (in Transaction tx,
    Amount sum_unspent) nothrow @safe;

/*******************************************************************************

    Calculates the fee of transaction data to store

    Params:
        data_size = The size of the data
        factor = The factor to calculate for the fee of transaction data

    Returns:
        A fee payable to data storage

*******************************************************************************/

public Amount calculateDataFee (ulong data_size, uint factor) pure nothrow @safe @nogc
{
    const ulong decimal = 100L;
    ulong fee = cast(ulong)(
        round(
            (
                exp((cast(double)data_size / cast(double)factor)) -
                1.0
            ) *
            decimal
        ) * 10_000_000L / decimal

    );
    return Amount(fee);
}

// Test for calculating a fee to store data
unittest
{
    // When the factor is 100
    assert(calculateDataFee(0, 100) == Amount(0L));
    assert(calculateDataFee(10, 100) == Amount(1_100_000L));
    assert(calculateDataFee(20, 100) == Amount(2_200_000L));
    assert(calculateDataFee(30, 100) == Amount(3_500_000L));
    assert(calculateDataFee(40, 100) == Amount(4_900_000L));
    assert(calculateDataFee(50, 100) == Amount(6_500_000L));
    assert(calculateDataFee(60, 100) == Amount(8_200_000L));
    assert(calculateDataFee(70, 100) == Amount(10_100_000L));
    assert(calculateDataFee(80, 100) == Amount(12_300_000L));
    assert(calculateDataFee(90, 100) == Amount(14_600_000L));
    assert(calculateDataFee(100, 100) == Amount(17_200_000L));
    assert(calculateDataFee(110, 100) == Amount(20_000_000L));
    assert(calculateDataFee(120, 100) == Amount(23_200_000L));
    assert(calculateDataFee(130, 100) == Amount(26_700_000L));
    assert(calculateDataFee(140, 100) == Amount(30_600_000L));
    assert(calculateDataFee(150, 100) == Amount(34_800_000L));
    assert(calculateDataFee(160, 100) == Amount(39_500_000L));
    assert(calculateDataFee(170, 100) == Amount(44_700_000L));
    assert(calculateDataFee(180, 100) == Amount(50_500_000L));
    assert(calculateDataFee(190, 100) == Amount(56_900_000L));
    assert(calculateDataFee(200, 100) == Amount(63_900_000L));
    assert(calculateDataFee(210, 100) == Amount(71_700_000L));
    assert(calculateDataFee(220, 100) == Amount(80_300_000L));
    assert(calculateDataFee(230, 100) == Amount(89_700_000L));
    assert(calculateDataFee(240, 100) == Amount(100_200_000L));
    assert(calculateDataFee(250, 100) == Amount(111_800_000L));
    assert(calculateDataFee(260, 100) == Amount(124_600_000L));
    assert(calculateDataFee(270, 100) == Amount(138_800_000L));
    assert(calculateDataFee(280, 100) == Amount(154_400_000L));
    assert(calculateDataFee(290, 100) == Amount(171_700_000L));
    assert(calculateDataFee(300, 100) == Amount(190_900_000L));
    assert(calculateDataFee(310, 100) == Amount(212_000_000L));
    assert(calculateDataFee(320, 100) == Amount(235_300_000L));
    assert(calculateDataFee(330, 100) == Amount(261_100_000L));
    assert(calculateDataFee(340, 100) == Amount(289_600_000L));
    assert(calculateDataFee(350, 100) == Amount(321_200_000L));
    assert(calculateDataFee(360, 100) == Amount(356_000_000L));
    assert(calculateDataFee(370, 100) == Amount(394_500_000L));
    assert(calculateDataFee(380, 100) == Amount(437_000_000L));
    assert(calculateDataFee(390, 100) == Amount(484_000_000L));
    assert(calculateDataFee(400, 100) == Amount(536_000_000L));
    assert(calculateDataFee(410, 100) == Amount(593_400_000L));
    assert(calculateDataFee(420, 100) == Amount(656_900_000L));
    assert(calculateDataFee(430, 100) == Amount(727_000_000L));
    assert(calculateDataFee(440, 100) == Amount(804_500_000L));
    assert(calculateDataFee(450, 100) == Amount(890_200_000L));
    assert(calculateDataFee(460, 100) == Amount(984_800_000L));
    assert(calculateDataFee(470, 100) == Amount(108_9500_000L));
    assert(calculateDataFee(480, 100) == Amount(1_205_100_000L));
    assert(calculateDataFee(490, 100) == Amount(1_332_900_000L));
    assert(calculateDataFee(500, 100) == Amount(1_474_100_000L));

    // When the factor is 200
    assert(calculateDataFee(0, 200) == Amount(0L));
    assert(calculateDataFee(10, 200) == Amount(500_000L));
    assert(calculateDataFee(20, 200) == Amount(1_100_000L));
    assert(calculateDataFee(30, 200) == Amount(1_600_000L));
    assert(calculateDataFee(40, 200) == Amount(2_200_000L));
    assert(calculateDataFee(50, 200) == Amount(2_800_000L));
    assert(calculateDataFee(60, 200) == Amount(3_500_000L));
    assert(calculateDataFee(70, 200) == Amount(4_200_000L));
    assert(calculateDataFee(80, 200) == Amount(4_900_000L));
    assert(calculateDataFee(90, 200) == Amount(5_700_000L));
    assert(calculateDataFee(100, 200) == Amount(6_500_000L));
    assert(calculateDataFee(110, 200) == Amount(7_300_000L));
    assert(calculateDataFee(120, 200) == Amount(8_200_000L));
    assert(calculateDataFee(130, 200) == Amount(9_200_000L));
    assert(calculateDataFee(140, 200) == Amount(10_100_000L));
    assert(calculateDataFee(150, 200) == Amount(11_200_000L));
    assert(calculateDataFee(160, 200) == Amount(12_300_000L));
    assert(calculateDataFee(170, 200) == Amount(13_400_000L));
    assert(calculateDataFee(180, 200) == Amount(14_600_000L));
    assert(calculateDataFee(190, 200) == Amount(15_900_000L));
    assert(calculateDataFee(200, 200) == Amount(17_200_000L));
    assert(calculateDataFee(210, 200) == Amount(18_600_000L));
    assert(calculateDataFee(220, 200) == Amount(20_000_000L));
    assert(calculateDataFee(230, 200) == Amount(21_600_000L));
    assert(calculateDataFee(240, 200) == Amount(23_200_000L));
    assert(calculateDataFee(250, 200) == Amount(24_900_000L));
    assert(calculateDataFee(260, 200) == Amount(26_700_000L));
    assert(calculateDataFee(270, 200) == Amount(28_600_000L));
    assert(calculateDataFee(280, 200) == Amount(30_600_000L));
    assert(calculateDataFee(290, 200) == Amount(32_600_000L));
    assert(calculateDataFee(300, 200) == Amount(34_800_000L));
    assert(calculateDataFee(310, 200) == Amount(37_100_000L));
    assert(calculateDataFee(320, 200) == Amount(39_500_000L));
    assert(calculateDataFee(330, 200) == Amount(42_100_000L));
    assert(calculateDataFee(340, 200) == Amount(44_700_000L));
    assert(calculateDataFee(350, 200) == Amount(47_500_000L));
    assert(calculateDataFee(360, 200) == Amount(50_500_000L));
    assert(calculateDataFee(370, 200) == Amount(53_600_000L));
    assert(calculateDataFee(380, 200) == Amount(56_900_000L));
    assert(calculateDataFee(390, 200) == Amount(60_300_000L));
    assert(calculateDataFee(400, 200) == Amount(63_900_000L));
    assert(calculateDataFee(410, 200) == Amount(67_700_000L));
    assert(calculateDataFee(420, 200) == Amount(71_700_000L));
    assert(calculateDataFee(430, 200) == Amount(75_800_000L));
    assert(calculateDataFee(440, 200) == Amount(80_300_000L));
    assert(calculateDataFee(450, 200) == Amount(84_900_000L));
    assert(calculateDataFee(460, 200) == Amount(89_700_000L));
    assert(calculateDataFee(470, 200) == Amount(94_900_000L));
    assert(calculateDataFee(480, 200) == Amount(10_020_0000L));
    assert(calculateDataFee(490, 200) == Amount(105_900_000L));
    assert(calculateDataFee(500, 200) == Amount(111_800_000L));
}

/*******************************************************************************

    A class that provides the ability to verify the `payload` field stored
    in a `Transaction`.

*******************************************************************************/

public class FeeManager
{
    /// SQLite db instance
    private ManagedDatabase db;

    /// Parameters for consensus-critical constants
    public immutable(ConsensusParams) params;

    /// Total Amount of fees accumulated per address
    private Amount[PublicKey] accumulated_fees;

    /// Ctor
    public this (ManagedDatabase db, immutable(ConsensusParams) params)
    {
        this.db = db;
        this.params = params;
        this.init();
    }

    /// Init DB and rebuild the in-memory state
    private void init ()
    {
        this.db.execute("CREATE TABLE IF NOT EXISTS accumulated_fees " ~
            "(public_key TEXT PRIMARY KEY, fee TEXT)");

        auto results = this.db.execute("SELECT public_key, fee " ~
            " FROM accumulated_fees");

        foreach (ref row; results)
        {
            const key = PublicKey.fromString(row.peek!(char[])(0));
            const fee = Amount.fromString(row.peek!(char[])(1));
            this.accumulated_fees[key] = fee;
        }
    }

    /***************************************************************************

        Checks the following in the data payload:

            Checks that the size of the data does not exceed
            the maximum size allowed.
            Checks if a commons budget address exists in the output.
            Checks if the appropriate fee is paid by commons budget address.

        Params:
            tx = `Transaction`
            tx_fee = transaction fee

        Return:
            `null` if the transaction is valid, a string explaining the reason it
            is invalid otherwise.

    ***************************************************************************/

    public string check (in Transaction tx, Amount tx_fee) nothrow @safe
    {
        Amount minimumFee = params.MinFee;
        if (!minimumFee.mul(tx.sizeInBytes()))
            return "Fee: Transaction size overflows fee cap";
        if (tx_fee < minimumFee)
            return "Transaction: Fee is less than adjusted minimum fee";

        if (tx.payload.length == 0)
            return null;

        if (tx.payload.length > this.params.TxPayloadMaxSize)
            return "Transaction: The size of the data payload is too large";

        const required_fee = calculateDataFee(tx.payload.length,
            this.params.TxPayloadFeeFactor);
        if (tx_fee < required_fee)
            return "Transaction: There is not enough data fee";

        return null;
    }

    /// Calculates the fee of data payloads
    public Amount getDataFee (ulong data_size) pure nothrow @safe @nogc
    {
        return calculateDataFee(data_size, this.params.TxPayloadFeeFactor);
    }

    /***************************************************************************

        Calculate the `Amount` of fees that should be paid to each Validator

        Params:
            tot_fee = Total amount of fees
            tot_data_fee = Total amount of data fees
            stakes = Staked UTXO of each Validator

        Return:
            `Amount` of fees that should be paid to each Validator

    ***************************************************************************/

    private Amount[] getValidatorFees (Amount tot_fee, Amount tot_data_fee,
        UTXO[] stakes) nothrow @safe
    {
        // no stakes, no fees
        if (stakes.length == 0)
            return [];

        // tx_fees = (tot_fee - tot_data_fee) * (ValidatorTXFeeCut / 100)
        Amount tx_fees = tot_fee;
        tx_fees.mustSub(tot_data_fee);
        tx_fees.percentage(this.params.ValidatorTXFeeCut);

        Amount sum_stake;
        Amount[] stake_amounts = stakes.map!(utxo => utxo.output.value).array;
        stake_amounts.each!(stake => sum_stake.mustAdd(stake));

        // Stake amount for a single "share"
        Amount share_stake = Amount.gcd(stake_amounts);
        // Total "share" count staked
        const total_shares = sum_stake.count(share_stake);

        // tx_fees now equals "share value"
        tx_fees.div(total_shares);

        ulong[] shares = stake_amounts.map!(stake => stake.count(share_stake)).array;

        Amount[] validator_fees;
        foreach (share; shares)
        {
            auto validator_fee = tx_fees;
            validator_fee.mul(share);
            validator_fees ~= validator_fee;
        }
        return validator_fees;
    }


    /***************************************************************************

        Calculate the `Amount` of fees that should be paid to
        `CommonsBudgetAddress`

        Params:
            tot_fee = Total amount of fees
            tot_data_fee = Total amount of data fees
            stakes = Staked UTXO of each Validator

        Return:
            `Amount` of fees that should be paid to `CommonsBudgetAddress`

    ***************************************************************************/

    public Amount getCommonsBudgetFee (Amount tot_fee, Amount tot_data_fee,
        UTXO[] stakes) nothrow @safe
    {
        const validator_fees = this.getValidatorFees(tot_fee, tot_data_fee,
            stakes);

        Amount total_val_fee;
        validator_fees.each!(fee => total_val_fee.mustAdd(fee));
        tot_fee.mustSub(total_val_fee);
        return tot_fee;
    }

    /***************************************************************************

        Calculate and accumulates the `Amount` of fees that should be paid to
        each Validator

        Params:
            block = Block to calculate the fees
            stakes = Staked UTXO of each Validator
            peekUTXO = delegate to find the UTXOs

        Return:
            `Amount` of fees that should be paid to each Validator

    ***************************************************************************/

    public void accumulateFees (in Block block, UTXO[] stakes,
        scope UTXOFinder peekUTXO) @trusted
    {
        if (block.header.height % this.params.PayoutPeriod == 0)
            this.clearAccumulatedFees();

        Amount tot_fee, tot_data_fee;
        this.getTXSetFees(block.txs, peekUTXO, tot_fee, tot_data_fee);

        const validator_fees = this.getValidatorFees(tot_fee, tot_data_fee,
            stakes);

        foreach (idx, stake; stakes)
        {
            this.accumulated_fees.update(stake.output.address,
                { return validator_fees[idx]; },
                (ref Amount so_far) {
                    so_far.mustAdd(validator_fees[idx]);
                    return so_far;
                }
            );

            this.db.execute(
                "REPLACE INTO accumulated_fees (fee, public_key) VALUES (?,?)",
                this.accumulated_fees[stake.output.address], stake.output.address);
        }
    }

    /***************************************************************************

        Returns the accumulated `Amount` of fees that should be paid on given
        height

        Params:
            height = requested height

        Return:
            `Amount` of fees that should be paid to each Validator

    ***************************************************************************/

    public Amount[PublicKey] getAccumulatedFees (in Height height) nothrow @safe
    {
        return height % this.params.PayoutPeriod == 0 ? this.accumulated_fees : null;
    }

    /// Clears the accumulated fees
    public void clearAccumulatedFees () @safe
    {
        () @trusted {
            this.db.execute("DELETE FROM accumulated_fees");
            this.accumulated_fees.clear();
        } ();
    }

    /***************************************************************************

        Calculate the transaction fee and adjust the fee based on the
        transaction's size measured in bytes.

        The bigger the transaction size is, the smaller the the fee becomes.

        Params:
            tx = transaction for which we want to calculate the adjusted fee
            peekUTXO = UTXO finder
            tot_fee = adjusted fee

        Returns: string describing the error, if an error happened, null otherwise

    ***************************************************************************/

    public string getAdjustedTXFee (in Transaction tx, scope UTXOFinder peekUTXO,
        out Amount tot_fee) nothrow @safe
    {
        Amount tot_data_fee;
        const(Transaction)[1] txs = [tx];

        auto res = this.getTXSetFees(txs, peekUTXO, tot_fee, tot_data_fee);
        tot_fee.div(tx.sizeInBytes());

        return res;
    }

    /***************************************************************************

        Calculate total fees of a Transaction set

        Params:
            tx_set = Transaction set
            peekUTXO = A delegate to query UTXOs
            tot_fee = Total fee (incl. data fees)
            tot_data_fee = Total data fee

        Returns: string describing the error, if an error happened, null otherwise

    ***************************************************************************/

    public string getTXSetFees (in Transaction[] tx_set,
        scope UTXOFinder peekUTXO, ref Amount tot_fee, ref Amount tot_data_fee)
        nothrow @safe
    {
        foreach (const ref tx; tx_set)
        {
            // Coinbase TXs are not subject to fees
            if (tx.isCoinbase)
                continue;

            Amount tot_in, tot_out;
            foreach (input; tx.inputs)
            {
                UTXO utxo;
                if (!peekUTXO(input.utxo, utxo))
                    return "Unable to find input for utxo";
                tot_in.mustAdd(utxo.output.value);
            }

            if (!tx.getSumOutput(tot_out))
                return "Transaction output value is invalid";
            // sum(inputs) - sum(outputs)
            tot_in.mustSub(tot_out);
            tot_fee.mustAdd(tot_in);
            tot_data_fee.mustAdd(this.getDataFee(tx.payload.length));
        }
        return null;
    }

    /// For unittest
    version (unittest) public this ()
    {
        this(new ManagedDatabase(":memory:"), new immutable(ConsensusParams));
    }

    /// For unittest
    version (unittest) public ManagedDatabase getDB ()
    {
        return this.db;
    }

    unittest
    {
        import std;
        import agora.crypto.Hash;
        import agora.utils.Test;

        auto man = new FeeManager();
        auto utxoset = new TestUTXOSet();

        Amount double_stake = Amount.MinFreezeAmount; assert(double_stake.mul(2));
        auto frozen_txs = [
            Transaction([], [Output(Amount.MinFreezeAmount,
                WK.Keys[0].address, OutputType.Freeze)]),
            Transaction([], [Output(Amount.MinFreezeAmount,
                WK.Keys[0].address, OutputType.Freeze)]),
            Transaction([], [Output(double_stake,
                WK.Keys[0].address, OutputType.Freeze)]),
        ];

        frozen_txs.each!(tx => utxoset.put(tx));
        auto keys = frozen_txs.map!(tx => UTXO.getHash(tx.hashFull(), 0));

        UTXO[] stakes;
        foreach (key; keys)
        {
            UTXO utxo;
            assert(utxoset.peekUTXO(key, utxo));
            stakes ~= utxo;
        }

        // When stakes are equal they should receive the same amount
        assert(man.getValidatorFees(Amount.UnitPerCoin, Amount(0),
            stakes[0..$-1]).uniq.array.length == 1);

        // 1 2X stake, 2 1X stakes
        auto fees = man.getValidatorFees(Amount.UnitPerCoin, Amount(0), stakes);
        assert(fees.length == stakes.length);

        fees = fees.uniq.array;
        assert(fees.length == 2);
        // Should be exactly double
        assert(fees[1].count(fees[0]) == 2);
        assert(fees[1].div(2) == Amount(0));

        // With some data fee
        Amount tot_fee = Amount.UnitPerCoin; assert(tot_fee.mul(2));
        auto w_data_fees = man.getValidatorFees(tot_fee,
            Amount.UnitPerCoin, stakes);
        auto commons_fee = man.getCommonsBudgetFee(tot_fee,
            Amount.UnitPerCoin, stakes);

        tot_fee.mustSub(commons_fee);
        foreach (fee; w_data_fees)
            tot_fee.mustSub(fee);
        // None wasted, none created
        assert(tot_fee == Amount(0));
    }
}

unittest
{
    import agora.consensus.state.UTXOCache;
    import agora.crypto.Hash;
    import agora.utils.Test;

    auto fee_man = new FeeManager();

    Transaction freeze_tx = Transaction(
        [ Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE2.address, OutputType.Freeze) ]);

    auto utxo_set = new TestUTXOSet;
    utxo_set.put(freeze_tx);

    Hash txhash = hashFull(freeze_tx);
    Hash stake_hash = UTXO.getHash(txhash, 0);

    Transaction gen_tx = Transaction(
        [ Output(Amount(2_000_000L), WK.Keys.NODE2.address) ]);
    utxo_set.put(gen_tx);

    Transaction spend_tx = Transaction(
        [ Input(gen_tx.hashFull(), 0)],
        [ Output(Amount(1_000_000L), WK.Keys.NODE2.address) ]);

    UTXO utxo;
    assert(utxo_set.peekUTXO(spend_tx.inputs[0].utxo, utxo));
    assert(utxo_set.peekUTXO(stake_hash, utxo));

    Block block;
    block.txs ~= spend_tx;

    fee_man.accumulateFees(block, [utxo], &utxo_set.peekUTXO);

    block.header.height = Height(1);
    fee_man.accumulateFees(block, [utxo], &utxo_set.peekUTXO);

    auto fee_man_2 = new FeeManager(fee_man.getDB(), new immutable(ConsensusParams));

    // fee_man_2 should recover from DB
    assert(fee_man.getAccumulatedFees(Height(0)) ==
        fee_man_2.getAccumulatedFees(Height(0)));
}
