/*******************************************************************************

    Defines the data structure of a block

    The design is influenced by Bitcoin, but will be ammended later.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.Block;

import agora.common.Amount;
import agora.common.BitMask;
import agora.common.Types;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Transaction;
import agora.crypto.ECC;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.crypto.Schnorr;
import agora.script.Lock;
import agora.serialization.Serializer;

import std.algorithm.comparison;
import std.algorithm.iteration;
import std.algorithm.searching;
import std.algorithm.sorting;
import std.range;

import core.bitop;

/*******************************************************************************

    The block header which contains a link to the previous block header,
    unless it's the genesis header.

*******************************************************************************/

public struct BlockHeader
{
    /// Hash of the previous block in the chain of blocks
    public Hash prev_block;

    /// The hash of the merkle root of the transactions
    public Hash merkle_root;

    /// Hash of random seed of the preimages for this height
    public Hash random_seed;

    /// Schnorr multisig of all validators which signed this block
    public Signature signature;

    /// BitMask containing the validators' key indices which signed the block
    public BitMask validators;

    /// Block height (genesis is #0)
    public Height height;

    /// Enrolled validators
    public Enrollment[] enrollments;

    /// List of indices to the validator UTXO set which have not revealed the preimage
    public uint[] missing_validators;

    /// Block seconds offset from Genesis Timestamp in `ConsensusParams`
    public ulong time_offset;

    /***************************************************************************

        Implements hashing support

        Note that validators bitmask bits & the signature are not hashed
        since they must sign the block header hash.

        Params:
            dg = Hashing function accumulator

    ***************************************************************************/

    public void computeHash (scope HashDg dg) const scope
        @safe pure nothrow @nogc
    {
        dg(this.prev_block[]);
        hashPart(this.height.value, dg);
        dg(this.merkle_root[]);
        foreach (enrollment; this.enrollments)
            hashPart(enrollment, dg);
        dg(this.random_seed[]);
        hashPart(this.validators.count, dg); // Include just the count of possible signers
        foreach (validator; this.missing_validators)
            hashPart(validator, dg);
        hashPart(this.time_offset, dg);
    }

    /***************************************************************************

        Create the block signature for the given keypair

        This signature will be combined with other validator's signatures
        using Schnorr multisig.

        Params:
            secret_key = node's secret
            preimage = preimage at the block height for the signing validator
            offset = enrollment cycle offset

    ***************************************************************************/

    public Signature createBlockSignature (in Scalar secret_key, in Hash preimage,
        ulong offset = 0) const @safe nothrow
    {
        // challenge = Hash(block) to Scalar
        const Scalar challenge = this.hashFull();
        // rc = r used in signing the commitment
        const Scalar rc = Scalar(hashMulti(secret_key, "consensus.signature.noise", offset));
        const Scalar reduced_preimage = Scalar(preimage);
        const Scalar r = rc + reduced_preimage; // make it unique for block height
        const Point R = r.toPoint();
        return sign(secret_key, R, r, challenge);
    }
}

/// hashing test
unittest
{
    import std.conv : to;
    auto address = `boa1xrra39xpg5q9zwhsq6u7pw508z2let6dj8r5lr4q0d0nff240fvd27yme3h`;
    PublicKey pubkey = PublicKey.fromString(address);

    Output[1] outputs = [ Output(Amount(100), pubkey) ];
    Transaction tx = Transaction(outputs[]);
    BlockHeader header = { merkle_root : tx.hashFull() };

    auto hash = hashFull(header);
    auto exp_hash = Hash("0x311b65a2f0b637034df2f50ec2961bc9948fc89072b74b66816704246e3d41dfb45c1077938a8a5a0541528d80106a679bc117caf776079c8c06d4fe5c7ca45c");
    assert(hash == exp_hash, hash.to!string);
}

/*******************************************************************************

    The block which contains the block header and its body (the transactions).

*******************************************************************************/

public struct Block
{
    // some unittests still assume a block contains 8 txs. Once they're fixed
    // this constant should be removed.
    version (unittest)
    {
        /// number of transactions that constitutes a block
        public enum TxsInTestBlock = 8;
    }

    ///
    public BlockHeader header;

    ///
    public Transaction[] txs;

    ///
    public Hash[] merkle_tree;

    /***************************************************************************

        Computes the hash matching this block

        The hash of a block is that of its header, however it is not uncommon
        that one call `hashFull` on the block instead of the header.
        As a result, this function simply forwards to the header.


        Params:
            dg = Hashing function accumulator

    ***************************************************************************/

    public void computeHash (scope HashDg dg) const scope
        @safe pure nothrow @nogc
    {
        hashPart(this.header, dg);
    }

    /***************************************************************************

        Returns:
            a copy of this block with a different signature and validators bitmask

        Params:
            signature = new signature
            validators = mask to indicate who has signed

    ***************************************************************************/

    public Block updateSignature (in Signature signature, BitMask validators)
        const @safe
    {
        return Block(
            BlockHeader(
                this.header.prev_block,
                this.header.merkle_root,
                this.header.random_seed,
                signature,
                validators,
                this.header.height,
                this.header.enrollments.dup,
                this.header.missing_validators.dup,
                this.header.time_offset),
            // TODO: Optimize this by using dup for txs also
            this.txs.map!(tx =>
                tx.serializeFull.deserializeFull!Transaction).array,
            this.merkle_tree.dup);
    }

    /***************************************************************************

        Block serialization

        Params:
            dg = serialize function accumulator

    ***************************************************************************/

    public void serialize (scope SerializeDg dg) const @safe
    {
        serializePart(this.header, dg);

        serializePart(this.txs.length, dg);
        foreach (ref tx; this.txs)
            serializePart(tx, dg);

        serializePart(this.merkle_tree.length, dg);
        foreach (ref merkle; this.merkle_tree)
            dg(merkle[]);
    }

    /***************************************************************************

        Build a merkle tree and its root, and store the tree to this Block

        Returns:
            the merkle root

    ***************************************************************************/

    public Hash buildMerkleTree () nothrow @safe
    {
        return Block.buildMerkleTree(this.txs, this.merkle_tree);
    }

    /***************************************************************************

        Returns:
            a number that is power 2 aligned. If the number is already a power
            of two it returns that number. Otherwise returns the next bigger
            number which is itself a power of 2.

    ***************************************************************************/

    private static size_t getPow2Aligned (size_t value) @safe @nogc nothrow pure
    in
    {
        assert(value > 0);
    }
    do
    {
        return bsr(value) == bsf(value) ? value : (1 << (bsr(value) + 1));
    }

    ///
    unittest
    {
        assert(getPow2Aligned(1) == 1);
        assert(getPow2Aligned(2) == 2);
        assert(getPow2Aligned(3) == 4);
        assert(getPow2Aligned(4) == 4);
        assert(getPow2Aligned(5) == 8);
        assert(getPow2Aligned(7) == 8);
        assert(getPow2Aligned(8) == 8);
        assert(getPow2Aligned(9) == 16);
        assert(getPow2Aligned(15) == 16);
        assert(getPow2Aligned(16) == 16);
        assert(getPow2Aligned(17) == 32);
    }

    /***************************************************************************

        Build a merkle tree and return its root

        Params:
            txs = the transactions to use
            merkle_tree = will contain the merkle tree on function return

        Returns:
            the merkle root

    ***************************************************************************/

    public static Hash buildMerkleTree (in Transaction[] txs,
        ref Hash[] merkle_tree) nothrow @safe
    {
        if (txs.length == 0)
        {
            merkle_tree.length = 0;
            return Hash.init;
        }

        immutable pow2_size = getPow2Aligned(txs.length);
        const MerkleLength = (pow2_size * 2) - 1;

        // 'new' instead of .length: workaround for issue #127 with ldc2 on osx
        merkle_tree = new Hash[](MerkleLength);

        return Block.buildMerkleTreeImpl(pow2_size, txs, merkle_tree);
    }

    /// Ditto
    private static Hash buildMerkleTreeImpl (in size_t pow2_size,
        in Transaction[] txs, ref Hash[] merkle_tree)
        nothrow @safe @nogc
    in
    {
        assert(txs !is null, "When calling buildMerkleTreeImpl, `txs` must not be null.");
    }
    do
    {
        assert(merkle_tree.length == (pow2_size * 2) - 1);

        const log2 = bsf(pow2_size);
        foreach (size_t idx, ref hash; merkle_tree[0 .. txs.length])
            hash = hashFull(txs[idx]);

        // transactions are ordered lexicographically by hash in the Merkle tree
        merkle_tree[0 .. txs.length].sort!("a < b");

        // repeat last hash if txs length was not a strict power of 2
        foreach (idx; txs.length .. pow2_size)
            merkle_tree[idx] = merkle_tree[txs.length - 1];

        immutable len = merkle_tree.length;
        for (size_t order = 0; order < log2; order++)
        {
            immutable start = len - (len >> (order));
            immutable end   = len - (len >> (order + 1));
            merkle_tree[start .. end].chunks(2)
                .map!(tup => hashMulti(tup[0], tup[1]))
                .enumerate(size_t(end))
                .each!((idx, val) => merkle_tree[idx] = val);
        }

        return merkle_tree[$ - 1];
    }

    /***************************************************************************

        Get merkle path

        Params:
            index = Sequence of transactions

        Returns:
            Return merkle path

    ***************************************************************************/

    public Hash[] getMerklePath (size_t index) const @safe nothrow
    {
        assert(this.merkle_tree.length != 0, "Block hasn't been fully initialized");

        immutable pow2_size = getPow2Aligned(this.txs.length);
        Hash[] merkle_path;
        size_t j = 0;
        for (size_t length = pow2_size; length > 1; length = (length + 1) / 2)
        {
            size_t i = min(index ^ 1, length - 1);
            merkle_path ~= this.merkle_tree[j + i];
            index >>= 1;
            j += length;
        }
        return merkle_path;
    }

    /***************************************************************************

        Calculate the merkle root using the merkle path.

        Params:
            hash = `Hash` of `Transaction`
            merkle_path  = `Hash` of merkle path
            index = Index of the hash in the array of transactions.

        Returns:
            Return `Hash` of merkle root.

    ***************************************************************************/

    public static Hash checkMerklePath (Hash hash, in Hash[] merkle_path, size_t index) @safe
    {
        foreach (const ref otherside; merkle_path)
        {
            if (index & 1)
                hash = hashMulti(otherside, hash);
            else
                hash = hashMulti(hash, otherside);

            index >>= 1;
        }

        return hash;
    }

    /***************************************************************************

        Find the sequence of transactions for the hash.

        Params:
            hash = `Hash` of `Transaction`

        Returns:
            Return sequence if found hash, otherwise Retrun the number of
            transactions.

    ***************************************************************************/

    public size_t findHashIndex (in Hash hash) const @safe nothrow
    {
        immutable pow2_size = getPow2Aligned(this.txs.length);
        assert(this.merkle_tree.length == (pow2_size * 2) - 1,
            "Block hasn't been fully initialized");

        auto index = this.merkle_tree[0 .. this.txs.length]
            .enumerate.assumeSorted.find!(res => res[1] == hash);

        return index.empty ? this.txs.length : index.front[0];
    }

    /// Returns a range of any freeze transactions in this block
    public auto frozens () const @safe pure nothrow
    {
        return this.txs.filter!(tx => tx.isFreeze);
    }

    /// Returns a range of any payment transactions in this block
    public auto payments () const @safe pure nothrow
    {
        return this.txs.filter!(tx => tx.isPayment);
    }
}

///
unittest
{
    import agora.crypto.Schnorr;
    immutable Hash merkle =
        Hash(`0xdb6e67f59fe0b30676037e4970705df8287f0de38298dcc09e50a8e85413` ~
        `959ca4c52a9fa1edbe6a47cbb6b5e9b2a19b4d0877cc1f5955a7166fe6884eecd2c3`);

    immutable address = `boa1xrra39xpg5q9zwhsq6u7pw508z2let6dj8r5lr4q0d0nff240fvd27yme3h`;
    PublicKey pubkey = PublicKey.fromString(address);

    Transaction tx = Transaction(
        [
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey)
        ]);

    auto validators = typeof(BlockHeader.validators)(6);
    validators[0] = true;
    validators[2] = true;
    validators[4] = true;

    Enrollment[] enrollments;
    enrollments ~= Enrollment.init;
    enrollments ~= Enrollment.init;

    Block block =
    {
        header:
        {
            prev_block:  Hash.init,
            height:      Height(0),
            merkle_root: merkle,
            validators:  validators,
            signature:   Signature.fromString(
                            "0x0f55e869b35fdd36a1f5147771c0c2f5ad35ec7b3e4e"
                            ~ "4f77bd37f1e0aef06d1a4b62ed5c610735b73e3175"
                            ~ "47ab3dc3402b05fd57419a2a5def798a03df2ef56a"),
            enrollments: enrollments,
        },
        txs: [ tx ],
        merkle_tree: [ merkle ],
    };
    testSymmetry!Block();
    testSymmetry(block);
    assert(block.header.validators[0]);
    assert(!block.header.validators[1]);
}

/*******************************************************************************

    Create a new block, referencing the provided previous block.

    Params:
        prev_block = the previous block
        txs = the transactions that will be contained in the new block
        time_offset = the block time offset from Genesis timestamp in seconds
        random_seed = Hash of random seed of the preimages
        validators = count of validators who could potentially sign the block
        enrollments = the enrollments that will be contained in the new block
        missing_validators = list of indices to the validator UTXO set
            which have not revealed the preimage

*******************************************************************************/

public Block makeNewBlock (Transactions)(const ref Block prev_block,
    Transactions txs, ulong time_offset, Hash random_seed, size_t validators,
    Enrollment[] enrollments = null, uint[] missing_validators = null)
    @safe nothrow
{
    static assert (isInputRange!Transactions);

    Block block;

    block.header.prev_block = prev_block.header.hashFull();
    block.header.height = prev_block.header.height + 1;
    block.header.time_offset = time_offset;
    block.header.random_seed = random_seed;
    block.header.validators = BitMask(validators);
    block.header.enrollments = enrollments;
    block.header.enrollments.sort!((a, b) => a.utxo_key < b.utxo_key);
    assert(block.header.enrollments.isStrictlyMonotonic!
        ("a.utxo_key < b.utxo_key"));  // there cannot be duplicates either

    block.header.missing_validators = missing_validators;
    block.header.missing_validators.sort!((a, b) => a < b);
    assert(block.header.missing_validators.isStrictlyMonotonic!
        ("a < b"));  // there cannot be duplicates either

    txs.each!(tx => block.txs ~= tx);
    block.txs.sort;

    block.header.merkle_root = block.buildMerkleTree();
    return block;
}

/// only used in unittests with some defaults
version (unittest)
{
    import agora.consensus.data.genesis.Test: genesis_validator_keys;
    import agora.consensus.validation.Block: wellKnownPreimages;

    public Block makeNewTestBlock (Transactions)(const ref Block prev_block,
        Transactions txs,
        in KeyPair[] key_pairs = genesis_validator_keys,
        Enrollment[] enrollments = null,
        uint[] missing_validators = null,
        ulong time_offset = 0) @safe nothrow
    {
        auto revealed = key_pairs.enumerate.filter!(en => !missing_validators.canFind(en.index)).map!(en => en.value).array;
        Hash[] pre_images = wellKnownPreimages(prev_block.header.height + 1, revealed);
        assert(revealed.length == key_pairs.length - missing_validators.length);
        try
        {
            Hash random_seed = pre_images.reduce!((a, b) => hashMulti(a, b));

            // the time_offset passed to makeNewBlock should really be
            // prev_block.header.time_offset + ConsensusParams.BlockInterval instead of
            // prev_block.header.time_offset + 1
            // however many tests calling makeNewTestBlock have no access to ConsensusParams
            auto block = makeNewBlock(prev_block, txs,
                    time_offset ? time_offset : prev_block.header.time_offset + 1,
                    random_seed, key_pairs.length, enrollments, missing_validators);
            auto validators = BitMask(key_pairs.length);
            Signature[] sigs;
            ulong offset = 0;
            key_pairs.enumerate.each!((i, k)
            {
                if (!missing_validators.canFind(i))
                {
                    validators[i] = true;
                    sigs ~= block.header.createBlockSignature(k.secret,
                        pre_images[i - missing_validators.filter!(m => m < i).count], offset);
                }
            });
            auto signed_block = block.updateSignature(multiSigCombine(sigs), validators);
            return signed_block;
        }
        catch (Exception e)
        {
            () @trusted
            {
                import std.format;
                assert(0, format!"makeNewTestBlock exception thrown during test: %s"(e));
            }();
        }
        return Block.init;
    }
}

///
@safe nothrow unittest
{
    import agora.consensus.data.genesis.Test;

    auto new_block = makeNewTestBlock(GenesisBlock, [Transaction.init]);
    auto rng_block = makeNewTestBlock(GenesisBlock, [Transaction.init].take(1));
    assert(new_block.header.prev_block == hashFull(GenesisBlock.header));
    assert(new_block == rng_block);

    Enrollment enr_1 =
    {
        utxo_key : Hash(
            "0x412ce227771d98240ffb0015ae49349670eded40267865c18f655db662d4e698f" ~
            "7caa4fcffdc5c068a07532637cf5042ae39b7af418847385480e620e1395986")
    };

    Enrollment enr_2 =
    {
        utxo_key : Hash(
            "0x412ce227771d98240ffb0015ae49349670eded40267865c18f655db662d4e698f" ~
            "7caa4fcffdc5c068a07532637cf5042ae39b7af418847385480e620e1395987")
    };

    auto random_seed = Hash("0x47c993d409aa7d77651ecaa5a5d29e47a7aee609c7" ~
                             "cb376f5f8ff2a868c738233a2df5ba11d635c8576a47" ~
                             "3864fc1c8fd1469f4be80b853764da53f6a5b41661");
    uint[] missing_validators = [];

    auto block = makeNewBlock(GenesisBlock, [Transaction.init], 1,
        random_seed, genesis_validator_keys.length, [enr_1, enr_2], missing_validators);
    assert(block.header.enrollments == [enr_1, enr_2]);  // ascending
    block = makeNewBlock(GenesisBlock, [Transaction.init], 1,
        random_seed, genesis_validator_keys.length, [enr_2, enr_1], missing_validators);
    assert(block.header.enrollments == [enr_1, enr_2]);  // ditto
}

///
@safe nothrow unittest
{
    import agora.consensus.data.genesis.Test;
    assert(GenesisBlock.header.hashFull() == GenesisBlock.hashFull());
}

/// Test of Merkle Path and Merkle Proof
unittest
{
    Transaction[] txs;
    Hash[] merkle_path;

    KeyPair[] key_pairs = [
        KeyPair.random(),
        KeyPair.random(),
        KeyPair.random(),
        KeyPair.random(),
        KeyPair.random(),
        KeyPair.random(),
        KeyPair.random(),
        KeyPair.random(),
        KeyPair.random()
    ];

    // Create transactions.
    Hash last_hash = Hash.init;
    for (int idx = 0; idx < 8; idx++)
    {
        auto tx = Transaction([Input(last_hash, 0)],[Output(Amount(100_000), key_pairs[idx+1].address)]);
        last_hash = hashFull(tx);
        tx.inputs[0].unlock = genKeyUnlock(
            key_pairs[idx].sign(last_hash[]));
        txs ~= tx;
    }

    Block block;

    block.header.prev_block = Hash.init;
    block.header.height = Height(0);
    block.txs ~= txs;
    block.header.merkle_root = block.buildMerkleTree();

    Hash[] hashes;
    hashes.reserve(txs.length);
    foreach (ref e; txs)
        hashes ~= hashFull(e);

    // transactions are ordered lexicographically by hash in the Merkle tree
    hashes.sort!("a < b");
    foreach (idx, hash; hashes)
        assert(block.findHashIndex(hash) == idx);

    const Hash ha = hashes[0];
    const Hash hb = hashes[1];
    const Hash hc = hashes[2];
    const Hash hd = hashes[3];
    const Hash he = hashes[4];
    const Hash hf = hashes[5];
    const Hash hg = hashes[6];
    const Hash hh = hashes[7];

    const Hash hab = hashMulti(ha, hb);
    const Hash hcd = hashMulti(hc, hd);
    const Hash hef = hashMulti(he, hf);
    const Hash hgh = hashMulti(hg, hh);

    const Hash habcd = hashMulti(hab, hcd);
    const Hash hefgh = hashMulti(hef, hgh);

    const Hash habcdefgh = hashMulti(habcd, hefgh);

    assert(block.header.merkle_root == habcdefgh);

    // Merkle Proof
    merkle_path = block.getMerklePath(2);
    assert(merkle_path.length == 3);
    assert(merkle_path[0] == hd);
    assert(merkle_path[1] == hab);
    assert(merkle_path[2] == hefgh);
    assert(block.header.merkle_root == Block.checkMerklePath(hc, merkle_path, 2));

    merkle_path = block.getMerklePath(4);
    assert(merkle_path.length == 3);
    assert(merkle_path[0] == hf);
    assert(merkle_path[1] == hgh);
    assert(merkle_path[2] == habcd);
    assert(block.header.merkle_root == Block.checkMerklePath(he, merkle_path, 4));
}

// test when the number of txs is not a strict power of 2
unittest
{
    auto kp = KeyPair.random();
    Transaction[] txs;
    Hash[] hashes;

    foreach (amount; 0 .. 9)
    {
        txs ~= Transaction(
            [Input(Hash.init, 0)],
            [Output(Amount(amount + 1), kp.address)]);
        hashes ~= hashFull(txs[$ - 1]);
    }

    Block block;
    block.txs = txs;
    block.header.merkle_root = block.buildMerkleTree();

    // transactions are ordered lexicographically by hash in the Merkle tree
    hashes.sort!("a < b");
    foreach (idx, hash; hashes)
        assert(block.findHashIndex(hash) == idx);

    const Hash ha = hashes[0];
    const Hash hb = hashes[1];
    const Hash hc = hashes[2];
    const Hash hd = hashes[3];
    const Hash he = hashes[4];
    const Hash hf = hashes[5];
    const Hash hg = hashes[6];
    const Hash hh = hashes[7];
    const Hash hi = hashes[8];
    const Hash hj = hashes[8];
    const Hash hk = hashes[8];
    const Hash hl = hashes[8];
    const Hash hm = hashes[8];
    const Hash hn = hashes[8];
    const Hash ho = hashes[8];
    const Hash hp = hashes[8];

    const Hash hab = hashMulti(ha, hb);
    const Hash hcd = hashMulti(hc, hd);
    const Hash hef = hashMulti(he, hf);
    const Hash hgh = hashMulti(hg, hh);
    const Hash hij = hashMulti(hi, hj);
    const Hash hkl = hashMulti(hk, hl);
    const Hash hmn = hashMulti(hm, hn);
    const Hash hop = hashMulti(ho, hp);

    const Hash habcd = hashMulti(hab, hcd);
    const Hash hefgh = hashMulti(hef, hgh);
    const Hash hijkl = hashMulti(hij, hkl);
    const Hash hmnop = hashMulti(hmn, hop);

    const Hash habcdefgh = hashMulti(habcd, hefgh);
    const Hash hijklmnop = hashMulti(hijkl, hmnop);

    const Hash habcdefghijklmnop = hashMulti(habcdefgh, hijklmnop);

    assert(block.header.merkle_root == habcdefghijklmnop);

    auto merkle_path = block.getMerklePath(2);
    assert(merkle_path.length == 4);
    assert(merkle_path[0] == hd);
    assert(merkle_path[1] == hab);
    assert(merkle_path[2] == hefgh);
    assert(merkle_path[3] == hijklmnop);
    assert(block.header.merkle_root == Block.checkMerklePath(hc, merkle_path, 2));

    merkle_path = block.getMerklePath(4);
    assert(merkle_path.length == 4);
    assert(merkle_path[0] == hf);
    assert(merkle_path[1] == hgh);
    assert(merkle_path[2] == habcd);
    assert(merkle_path[3] == hijklmnop);
    assert(block.header.merkle_root == Block.checkMerklePath(he, merkle_path, 4));

    merkle_path = block.getMerklePath(8);
    assert(merkle_path.length == 4);
    assert(merkle_path[0] == hj);
    assert(merkle_path[1] == hkl);
    assert(merkle_path[2] == hmnop);
    assert(merkle_path[3] == habcdefgh);
    assert(block.header.merkle_root == Block.checkMerklePath(hi, merkle_path, 8));
}

/// demonstrate signing two blocks at height 1 to reveal private node key
unittest
{
    import agora.consensus.data.genesis.Test: GenesisBlock;
    import agora.crypto.ECC: Scalar, Point;
    import agora.crypto.Schnorr;
    import agora.utils.Test;
    import std.format;

    Hash random_seed1 = "seed1".hashFull();
    Hash random_seed2 = "seed2".hashFull();
    Hash preimage = "preimage".hashFull();

    const TimeOffset = 1;
    const Validators = genesis_validator_keys.length;

    // Generate two blocks at height 1
    auto block1 = GenesisBlock.makeNewBlock(
        genesisSpendable().take(1).map!(txb => txb.sign()), TimeOffset, random_seed1, Validators);
    auto block2 = GenesisBlock.makeNewBlock(
        genesisSpendable().take(1).map!(txb => txb.sign()), TimeOffset, random_seed2, Validators);

    Scalar v = genesis_validator_keys[0].secret;
    assert(v.isValid(), "v is not a valid Scalar!");
    Point V = v.toPoint();
    const Scalar rc = Scalar(hashMulti(v, "consensus.signature.noise", 0));
    const Scalar r = rc + Scalar(preimage);
    const Point R = r.toPoint();

    // Two messages
    Scalar c1 = block1.hashFull();
    Scalar c2 = block2.hashFull();
    assert(c1 != c2);

    // Sign with same r twice
    Signature sig1 = block1.header.createBlockSignature(v, preimage);
    Signature sig2 = block2.header.createBlockSignature(v, preimage);

    // Verify signatures
    assert(verify(sig1, c1, V));
    assert(verify(sig2, c2, V));

    // Calculate the private key by subtraction
    // `s = r + (v * c)`
    // `s1 - s2 = r + (v * c1) - (r + v * c2) = v(c1 - c2)`
    // `v = (s1 - s2) / (c1 - c2)`
    Scalar s = (sig1.s - sig2.s);
    Scalar c = (c1 - c2);

    Scalar secret = s * c.invert();
    assert(secret == v,
        format!"Key %s is not matching key %s"
        (secret.toString(PrintMode.Clear), v.toString(PrintMode.Clear)));
}
