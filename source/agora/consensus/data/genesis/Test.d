/*******************************************************************************

    Defines a genesis block suitable for testing purpose

    This genesis block is used in multiple places:
    - Unittests;
    - Network unittests (modules `agora.test`);
    - The system unit tests;
    - The system integration tests;

    The keys in this module are well-known, and hence not suitable for anything
    that isn't a test.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.genesis.Test;

import agora.common.Amount;
import agora.common.BitMask;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Transaction;
import agora.crypto.ECC;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.crypto.Schnorr: Signature;
import agora.utils.Test;

/*******************************************************************************

    The genesis block as used by most tests

    Note that this is more of a 'test' block than a 'unittest' block,
    and it's currently used in a few integration test, hence why it is not
    `version (unittest)`.
    It can also be used for system integration testing.

    It contains a total of 500M initial coins, of which 12M have been frozen
    among 6 nodes, and the rest is evenly split between 8 outputs (61M each).

*******************************************************************************/

public immutable Block GenesisBlock = {
    header: {
        prev_block:  Hash.init,
        height:      Height(0),
        merkle_root: GenesisMerkleTree[$ - 1],
        time_offset: 0, // In subsequent blocks this will be the offset in seconds from Genesis time
        validators:  BitMask(0),
        signature:   Signature.init,
        enrollments: [
            // boa1xrval7gwhjz4k9raqukcnv2n4rl4fxt74m2y9eay6l5mqdf4gntnzhhscrh
            Enrollment(
                Hash(`0x210f6551d648a4da654da116b100e941e434e4f232b8579439c2ef64b04819bd2782eb3524c7a29c38c347cdf26006bccac54a58a58f103ae7eb5b252eb53b64`),
                Hash(`0x0d74a7d76f9157f307e9f9b2792931479ba62bfed768e1e21675ebd20f8db701444bb319e037913a378f913e65611710ac8ad26251807ae2e288ffa1d6d30a8e`),
                20,
                Signature.fromString(`0x018389f5876ebac77ad4c2269415bf8a5b14e2374e9d30a933f70a10abbca2a40d08f22685c3a3a32ffca59d769ccfcc593a215423f17423596f29f40b6da67c`)),
            // boa1xzval2a3cdxv28n6slr62wlczslk3juvk7cu05qt3z55ty2rlfqfc6egsh2
            Enrollment(
                Hash(`0x3b44d65edb3361dd91441ab4f449eeda55644026624c4b8ae12ecf0264fa8a228dbf672ef97e2c4f87fb98ad7099e17b7f9ba7dbe8479672066912b1ea24ba77`),
                Hash(`0x45a81942081ea00788a26187464fa79f6cefc3c09417167c64f638010ab40728d671c1725c6b30770e67a91688ab936a2bc1a402cf4cd2ffffa48f6c199f6332`),
                20,
                Signature.fromString(`0xe3f959407fe99cb23f352be4477bbef8f619a11283319192418ac869eeb204060fdb2a50fc1fb3c089cfe41ebd50a773d9bf677c3721a643c4559e148617ac00`)),
            // boa1xzval3ah8z7ewhuzx6mywveyr79f24w49rdypwgurhjkr8z2ke2mycftv9n
            Enrollment(
                Hash(`0x7bacc99e9bf827f0fa6dc6a77303d2e6ba6f1591277b896a9305a9e200853986fe9527fd551077a4ac2b511633ada4190a7b82cddaf606171336e1efba87ea8f`),
                Hash(`0x072582e862efa9daf7a53a100989a07ad0ee0f0d5bfadf74909d6a6b3cf3c7a7e5d2e218f51df416d052b486e0d65608cbe70e51f0372fd211d68f353d299c0c`),
                20,
                Signature.fromString(`0x375eefbe1990a6e37b2f9a11b1ba68e3c8f8d0976f51a5de55e4d58a6798cd4f06939493c0bc804b01a43e2ae9986a21acdb774d751c447151864e8be369ea05`)),
            // boa1xrval6hd8szdektyz69fnqjwqfejhu4rvrpwlahh9rhaazzpvs5g6lh34l5
            Enrollment(
                Hash(`0x9b2726e79f05abc107b6531486a46c977414e13ed9f3ee994ec14504964f86fcf9464055b891b9c34020feb72535c300ff19e8b5167eb9d202db1a053d746b2c`),
                Hash(`0xe2f3bf5daf2d2522289cc93901e7a9d4fd5df8e85efa93960fa8eb46a85a45781f3121bb895fa5203108f3d690d21085f9c1cfccbd98de9b8e7e95ae070bcf5d`),
                20,
                Signature.fromString(`0xa72ed0e4b392632c51a923a79b319d9db6c5269319bb94ecff4588c18d0a9a1c061ce321f68446de79b7379dbf681a16cf177abf1990b08a7082b21bc58892b5`)),
            // boa1xrval5rzmma29zh4aqgv3mvcarhwa0w8rgthy3l9vaj3fywf9894ycmjkm8
            Enrollment(
                Hash(`0xab19131ad8974a20881e2cd0798684a06ca0054160735cdf67fe8ee5a0eb4e28e9bf3f4c735f9ed3da958778978c86b409b8d133f30992141f0ac7e01e7f1255`),
                Hash(`0x27892eed27841003e3a5a6ad1e6de90fcb2bc0627ca138bdc0b12b1bbb413e3ca06331de912a90a5787a602511fbf5663903b8fee57f6b1f1978f93439e237bb`),
                20,
                Signature.fromString(`0xe9a3c6c63d9810e61561fb7e4379849d57d7d47942d6ca4ecf993ad7aafe76f50270740f6af19641a4ce04dea9e03bfb1253b9c5885a58a0fc471375e2d9d55f`)),
            // boa1xzval4nvru2ej9m0rptq7hatukkavemryvct4f8smyy3ky9ct5u0s8w6gfy
            Enrollment(
                Hash(`0xdb7664caba94c8d4602c10992c13176307e1e05361c150217166ee77fc4af9bf176f31dc61aba61e634dfc0b4c5f729d59e604607f61c9f66b10c6841f972a0a`),
                Hash(`0x672401404e947aaae126a9e8c150facf0fea6d7b607725f4ada6de369fdd54d8079c2555ed52f80e160f9c78b5f650372d01daa765924a5e50a0db530a58e510`),
                20,
                Signature.fromString(`0x07ffcebf03b8e7c2f14209f0999bfbd80f2704d69d1383434c9c0ff7f52ad22c00ccee67457d3154fe7e2cc32a35d5e1441ebacc98fbfb4f30969e536f79d225`)),
        ],
    },
    merkle_tree: GenesisMerkleTree,
    txs: [
        Transaction(
            [
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
            ]),
        Transaction(
            [
                // If we want these in order NODE2, NODE3 .. NODE7
                // then we need to make sure the value of the Public key is in same order
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE2.address, OutputType.Freeze),
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE3.address, OutputType.Freeze),
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE4.address, OutputType.Freeze),
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE5.address, OutputType.Freeze),
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE6.address, OutputType.Freeze),
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE7.address, OutputType.Freeze),
            ]),
    ],
};

///
unittest
{
    import agora.serialization.Serializer;
    import std.conv;
    import std.algorithm.sorting : isSorted;

    Block block = GenesisBlock.serializeFull.deserializeFull!Block;

    assert(GenesisBlock.header.prev_block == Hash.init);
    assert(GenesisBlock.header.height == 0);
    assert(GenesisBlock.txs.isSorted(), "Block transaction must be sorted!");
    assert(GenesisBlock.merkle_tree.length == 3);
    Hash[] merkle_tree;
    GenesisBlock.buildMerkleTree(GenesisBlock.txs, merkle_tree);
    assert(merkle_tree == GenesisMerkleTree, merkle_tree.to!string);
}

///
unittest
{
    import std.algorithm;

    Amount amount;
    assert(GenesisBlock.txs.all!(tx => tx.getSumOutput(amount)));
    assert(amount == Amount(500_000_000_0000000), amount.toString());
    assert(GenesisBlock.merkle_tree.length == GenesisMerkleTree.length);
    assert(GenesisBlock.header.merkle_root == GenesisBlock.merkle_tree[$-1]);
}

private immutable Hash[] GenesisMerkleTree = [
    Hash(`0x26866bb263593d024a92103646c48cf35a2b1bfcc49b087915b85db14a432b373569d56f576242354328a31bf0102a0a78cb806cf6e25d88d7981367833631b7`),
    Hash(`0xeb5e0004d046422c84ddb7b9d54a0eba484a41b5179beda0b3dd7c54c3fca609437a9c8ef16b5bfc2335d9b258eb68908757e0f1a4c725752598aaa962924551`),
    Hash(`0xaf402f71c175bc6f53ededdd9cfa1f4c074efcd2fe7090c9d0ca3b95c5d1e7513cd4b4f922c4f7ebf120958f449a2d3e23a397c7219e297b8ff1cfbc00ebc93d`)
];

/// GDGENES4KXH7RQJELTONR7HSVISVSQ5POSVBEWLR6EEIIL72H24IEDT4
private immutable PublicKey GenesisOutputAddress = WK.Keys.Genesis.address;

/// GDCOMMO272NFWHV5TQAIQFEDLQZLBMVVOJTHC3F567ZX4ZSRQQQWGLI3
public immutable PublicKey CommonsBudgetAddress = WK.Keys.CommonsBudget.address;

unittest
{
    import agora.serialization.Serializer;
    testSymmetry(GenesisBlock.txs[0]);
    testSymmetry(GenesisBlock.txs[1]);
    testSymmetry(GenesisBlock);
}

// These are the genesis validators ordered to match Genesis enrollments
public immutable KeyPair[] genesis_validator_keys = [
    WK.Keys.NODE7,
    WK.Keys.NODE2,
    WK.Keys.NODE3,
    WK.Keys.NODE6,
    WK.Keys.NODE5,
    WK.Keys.NODE4,
];
