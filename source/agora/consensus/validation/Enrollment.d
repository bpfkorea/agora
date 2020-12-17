
/*******************************************************************************

    Contains validation routines for enrollments

    Copyright:
        Copyright (c) 2019-2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.validation.Enrollment;

import agora.common.Amount;
import agora.common.Types;
import agora.common.crypto.ECC;
import agora.common.crypto.Key;
import agora.common.crypto.Schnorr;
import agora.consensus.data.Enrollment;
import agora.consensus.state.UTXOSet;

import std.conv;

version (unittest)
{
    import agora.common.Hash;
    import agora.consensus.data.Transaction;
}

/*******************************************************************************

    Check the validity of an enrollment.

    A Validator's enrollment is considered valid if:
        - UTXO is unspent frozen utxo
        - Signatures are authentic
        - The frozen amount must be equal to or greater than 40,000 BOA

    Params:
        enrollment = The enrollment of the target to be verified
        findUTXO = delegate to find the referenced unspent UTXOs with

    Returns:
        `null` if the validator's UTXO is valid, otherwise a string
        explaining the reason it is invalid.

*******************************************************************************/

public string isInvalidReason (const ref Enrollment enrollment,
    scope UTXOFinder findUTXO) nothrow @safe
{
    UTXO utxo_set_value;
    if (!findUTXO(enrollment.utxo_key, utxo_set_value))
        return "Enrollment: UTXO not found";

    if (utxo_set_value.type != typeof(utxo_set_value.type).Freeze)
        return "Enrollment: UTXO is not frozen";

    Point address;
    try
    {
        address = Point(utxo_set_value.output.address);
    }
    catch (Exception ex)
    {
        return "Enrollment: Cannot convert address to point";
    }

    if (!verify(address, enrollment.enroll_sig, enrollment))
        return "Enrollment: signature verification failed";

    if (utxo_set_value.output.value.integral() < Amount.MinFreezeAmount.integral())
    {
        static immutable Message =
            "Enrollment: The frozen amount must be equal to or greater than " ~
            Amount.MinFreezeAmount.integral().to!string ~ " BOA";
        return Message;
    }

    if (enrollment.cycle_length == 0 || enrollment.cycle_length == uint.max)
        return "Enrollment: Invalid cycle length";

    return null;
}

/// Ditto but returns `bool`, only usable in unittests
version (unittest)
public bool isValid (const ref Enrollment enrollment,
    scope UTXOFinder findUTXO) nothrow @safe
{
    return isInvalidReason(enrollment, findUTXO) is null;
}

///
unittest
{
    import std.algorithm.searching;
    import std.string;

    KeyPair[] key_pairs = [KeyPair.random, KeyPair.random, KeyPair.random, KeyPair.random];

    scope utxo_set = new TestUTXOSet();
    scope UTXOFinder utxoFinder = utxo_set.getUTXOFinder();

    // normal frozen transaction
    Transaction tx1 = Transaction(
        TxType.Freeze,
        [Input(Hash.init, 0)],
        [Output(Amount.MinFreezeAmount, key_pairs[0].address)]
    );

    // payment transaction
    Transaction tx2 = Transaction(
        TxType.Payment,
        [Input(Hash.init, 0)],
        [Output(Amount.MinFreezeAmount, key_pairs[1].address)]
    );

    // Insufficient freeze amount transaction
    Transaction tx3 = Transaction(
        TxType.Freeze,
        [Input(Hash.init, 0)],
        [Output(Amount(1), key_pairs[2].address)]
    );

    // normal freeze amount transaction
    Transaction tx4 = Transaction(
        TxType.Freeze,
        [Input(Hash.init, 0)],
        [Output(Amount.MinFreezeAmount, key_pairs[3].address)]
    );

    auto utxo_hash1 = UTXO.getHash(hashFull(tx1), 0);
    auto utxo_hash2 = UTXO.getHash(hashFull(tx2), 0);
    auto utxo_hash3 = UTXO.getHash(hashFull(tx3), 0);
    auto utxo_hash4 = UTXO.getHash(hashFull(tx4), 0);

    Pair signature_noise = Pair.random;

    Pair node_key_pair_1 = Pair.fromScalar(secretKeyToCurveScalar(key_pairs[0].secret));

    Enrollment enroll1;
    enroll1.utxo_key = utxo_hash1;
    enroll1.random_seed = hashFull(Scalar.random());
    enroll1.cycle_length = 1008;
    enroll1.enroll_sig = sign(node_key_pair_1, signature_noise, enroll1);

    Pair node_key_pair_2 = Pair.fromScalar(secretKeyToCurveScalar(key_pairs[1].secret));

    Enrollment enroll2;
    enroll2.utxo_key = utxo_hash2;
    enroll2.random_seed = hashFull(Scalar.random());
    enroll2.cycle_length = 1008;
    enroll2.enroll_sig = sign(node_key_pair_2, signature_noise, enroll2);

    Pair node_key_pair_3 = Pair.fromScalar(secretKeyToCurveScalar(key_pairs[2].secret));

    Enrollment enroll3;
    enroll3.utxo_key = utxo_hash3;
    enroll3.random_seed = hashFull(Scalar.random());
    enroll3.cycle_length = 1008;
    enroll3.enroll_sig = sign(node_key_pair_3, signature_noise, enroll3);

    // Make pair with non matching scalar and point
    Pair node_key_pair_invalid = Pair(node_key_pair_2.v, node_key_pair_3.V);

    Enrollment enroll4;
    enroll4.utxo_key = utxo_hash4;
    enroll4.random_seed = hashFull(Scalar.random());
    enroll4.cycle_length = 1008;
    enroll4.enroll_sig = sign(node_key_pair_invalid, signature_noise, enroll4);

    assert(!enroll1.isValid(utxoFinder));
    assert(!enroll2.isValid(utxoFinder));
    assert(!enroll3.isValid(utxoFinder));
    assert(!enroll4.isValid(utxoFinder));

    utxo_set.put(tx1);
    utxo_set.put(tx2);
    utxo_set.put(tx3);
    utxo_set.put(tx4);

    // Nomal
    assert(enroll1.isValid(utxoFinder));

    // Unspent frozen UTXO not found for the validator.
    assert(!enroll1.isValid( utxoFinder));

    // UTXO is not frozen.
    assert(canFind(enroll2.isInvalidReason(utxoFinder), "UTXO is not frozen"));

    // The frozen amount must be equal to or greater than 40,000 BOA.
    assert(!enroll3.isValid(utxoFinder));

    // Enrollment signature verification has an error.
    assert(!enroll4.isValid(utxoFinder));
}
