/*******************************************************************************

    Defines the genesis block used by the live network (CoinNet)

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.genesis.Coinnet;

import agora.common.Amount;
import agora.common.BitMask;
import agora.common.Types;
import agora.crypto.Schnorr: Signature;
import agora.crypto.ECC;
import agora.consensus.data.Block;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Transaction;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.utils.Test;

/// The genesis block as defined by CoinNet
public immutable Block GenesisBlock =
{
    header:
    {
        prev_block:  Hash.init,
        height:      Height(0),
        merkle_root: GenesisMerkleRoot,
        enrollments: Enrollments,
        validators:  BitMask(0),    // Validators do not sign GenesisBlock
        signature:   Signature.init,
        time_offset: 0, // In subsequent blocks this will be the offset in seconds from Genesis time
    },
    txs: GenesisTransactions,
    merkle_tree: GenesisMerkleTree,
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

// TODO: Replace with the node's enrollments
/// The enrollments that are part of the genesis block
private immutable Enrollment[] Enrollments =
    [
        // boa1xzd7zmk7rnun06psp9d0r0p0lj2m6zfz63w55pguzlem7nkv274e6hn2hg3
        Enrollment(
            Hash(`0x2bc74413d4eceb3db7ef48724e9085f7c60b3438c7fdb6052585dcfc5b325bb6587c7e5d98a54f029841b4f4db48fb7b66ea99fc87155ceba9bcea42ee1cdbaf`),
            Hash(`0xa6db9318eb655c4c76626150475a2084743e138bf66f35181450e774f427fe503d93b9d63c744d6e524a9a289ccda8b439e4ec8c63f706ca2e1457b76ad474db`),
            1008,
            Signature.fromString(`0xbcab099143e5161f6a7861601a7dd3f834d6a6ff9dab1e48ac05d02c8c993c0e0ee253e87bbd5a98862f7abae7cf1c28b59fd748bb4e6984d054547e12f3ccd1`)),
        // boa1xzdaz4hx35kmp7zfd854yf98hx6ksdv3ps363dunvfl6l39m4v63qmyccsm
        Enrollment(
            Hash(`0x4a4f31d2a5ec190c5e265fb50f476ba765c3da173022e42e54095feefb729a4ac80f592788ac23d5c42a837d227070cfabbc5cb5914fe0044d2d93fdbbbecc31`),
            Hash(`0xa7e7f85bb5c4bec7a815adfac780b6cba5a9968eefd4d14383edf9bfa593a4289f570776df8e7789c07733a6b83be953219e3882c240efd9cd6355019488bc9a`),
            1008,
            Signature.fromString(`0x39fc8b1202724ee3d09e2815199ae6a1424f8d84a0987760e87eca04951de58b00e695f3652e6f821bccf52ab3cb786bde73f970a90439442dca3f1613e38ac9`)),
        // boa1xzdlzl5znnssm3dlslqgrayrl4frdmh0s7dyqwgvkdqaqkf5994aw53cn58
        Enrollment(
            Hash(`0x9301380ac22ce13428e89a814c65be405e13b0018a24e9cda865a0c909b94070de66c1f6aa7912817fe892ce3f2aaa6eaa5a362e490659b3890e0897def32d33`),
            Hash(`0xeb87c728d5e16bcd1306256190eb983be3dfed4809c9be277f1ecb39d66c7563c68d66eb29548badd8f1d18105c58a0e4d3a7c2f8ebf00190d56f095295b35b1`),
            1008,
            Signature.fromString(`0xcc1d153578be5cd72e52d51a5b71f4802d574da2be4f015764aae44f39180f9a0d05195b8ee5f827fbc45a163836de2f76545f46b70607bd9fb914d14b1a50c4`)),
        // boa1xzdmznw099p8e2h54pe8ed7599c99qez0f2m756ecmtamqtlq0vm73jg5mj
        Enrollment(
            Hash(`0xa7f6179d9e78e50ea4c7acb7b9acceff4f2d99467e7d30bda57ad985700738ee80d127d65d685cd684ab95d4e53a986eb4a711bf6b432fd9d6ace1985f99ea26`),
            Hash(`0xbab8b55833dea8cc341989d21fa13e957aa12bf50358e7b4e9a1c2b80e2f48cc9ebee3639db164c79b8b1401b216065c1083f3f2529f61e980ef25a752d7734d`),
            1008,
            Signature.fromString(`0xf45c14a6f9220b53128f1f08aa666ddefd125ccf2512015937a2b97248f25ce902131c2d9a2d7d57f50125ec83c38b2b226eb8243135f43924c7a1e546b00801`)),
        // boa1xzd6zuhueq5nyd0m4c4qm66az5dyq8r29hrynd3phezh50gf5c7u54eqtdh
        Enrollment(
            Hash(`0xcecbebc5b219d0d11e12b1213336a0fbdcf01ae5996a38da69ed12246ce2380757d34e5aac35c9a943d97343b400b777e6f32c1f6e052dc983565f8e3684febf`),
            Hash(`0x12db13cb5232ae53096ced2ef1bed83b50774c83561ec74fcbefea70814189f39bc55f5555ff8ba95d2424e1790c38a5aa7f7ffa37dfd1baf834b0b35d7b0ca5`),
            1008,
            Signature.fromString(`0x6633727a9a0b55b2dafbdd951682b089b2b45b9644d09522370c6f1c4e2c9b2f070e39b034bf63af197809832c2cd5bea7bc81f86daf00c0d26cc7a3db5bbf0f`)),
        // boa1xzduznmm7kp7gg20azr8k9c9pzdwapx6culll96s8dqah5kj5cjsj0le8rk
        Enrollment(
            Hash(`0xe1797e8a4f21502777ae1fdd25aa0bed6d4cccab4fc0abdded9079b3305ded3cb047f075c2b2ce8402d53c29935913712f3b3b9fcb7bcd635a59d736df2085ca`),
            Hash(`0x22125b349ec3b88403cc7bd6ff5d33173b12189a8cd1c489c5349db71f6fa00f91606ea71a69988f4812e7610529672f4150354c2f346b554a7d6edd6fa3af64`),
            1008,
            Signature.fromString(`0x907ef65138cae7cad57d9c6804700188f66f69cfb7c4b283e4cf380a8067a23f0e551331f946632a4ccafa7b14a013ccc8407d7c17778dbae7ffefba8278df31`)),
    ];

///
private immutable Hash GenesisMerkleRoot = GenesisMerkleTree[$ - 1];

///
private immutable Transaction[] GenesisTransactions =
    [
        Transaction(
            [
                Output(Amount(54_750_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(54_750_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(54_750_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(54_750_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(54_750_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(54_750_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(54_750_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(54_750_000L * 10_000_000L), GenesisOutputAddress),
            ]),
        Transaction(
            [
                Output(Amount(2_000_000L * 10_000_000L), NODE2_ADDRESS, OutputType.Freeze),
                Output(Amount(2_000_000L * 10_000_000L), NODE3_ADDRESS, OutputType.Freeze),
                Output(Amount(2_000_000L * 10_000_000L), NODE4_ADDRESS, OutputType.Freeze),
                Output(Amount(2_000_000L * 10_000_000L), NODE5_ADDRESS, OutputType.Freeze),
                Output(Amount(2_000_000L * 10_000_000L), NODE6_ADDRESS, OutputType.Freeze),
                Output(Amount(2_000_000L * 10_000_000L), NODE7_ADDRESS, OutputType.Freeze),
            ]),
    ];

private immutable Hash[] GenesisMerkleTree = [
    Hash(`0x539dab37f74322d84c0268c71be625dc01b550968022c6ec80163399162feb04ddc6eb2ce70e5e512081900cd46b01a14f25f61ddcfd678b32b5f3c918890c84`),
    Hash(`0xd138ebeb4c21aacedf15e4cfd335d06ef7c08934252c5a16c2662017764dc73d9ec2176038e38a7be4b982986a49884ed525b9d3be13dd86bf3660bf14d0174e`),
    Hash(`0x291bee5e2d3e728090403e6689f0f0b7d6c2031e5d6bbed9fae5cb6f42d292bb375d2ddffc00f25ef55a9cddfaac9c5a6bc39bfc219bbd879bf7e73b765785c5`),
];

// TODO: Replace with the foundation's pubkey
/// GDGENYO6TWO6EZG2OXEBVDCNKLHCV2UFLLZY6TJMWTGR23UMJHVHLHKJ
private immutable PublicKey GenesisOutputAddress = GenesisAddressUbyte;

///
private immutable ubyte[] GenesisAddressUbyte = [
    204, 70, 225, 222, 157, 157, 226, 100,
    218, 117, 200, 26, 140, 77, 82, 206,
    42, 234, 133, 90, 243, 143, 77, 44,
    180, 205, 29, 110, 140, 73, 234, 117
    ];

unittest
{
    assert(GenesisOutputAddress.toString()
           == `boa1xrxydcw7nkw7yex6whyp4rzd2t8z4659ttec7nfvknx36m5vf8482hvnkxh`);
}


/// GCOMBBXA6ON7PT7APS4IWS4N53FCBQTLWBPIU4JR2DSOBCA72WEB4XU4
public immutable PublicKey CommonsBudgetAddress = CommonsBudgetUbyte;

///
private immutable ubyte[] CommonsBudgetUbyte = [
    156, 192, 134, 224, 243, 155, 247, 207,
    224, 124, 184, 139, 75, 141, 238, 202,
    32, 194, 107, 176, 94, 138, 113, 49,
    208, 228, 224, 136, 31, 213, 136, 30];

unittest
{
    assert(CommonsBudgetAddress.toString()
           == `boa1xzwvpphq7wdl0nlq0jugkjudam9zpsntkp0g5uf36rjwpzql6kypuddc9vr`);
}

unittest
{
    import agora.serialization.Serializer;
    testSymmetry(GenesisTransactions);
    testSymmetry(GenesisBlock);
}

// TODO: Replace with the node's pubkey
/// NODE2: GCN2C4X4ZAUTENP3VYVA3225CUNEAHDKFXDETNRBXZCXUPIJUY64UANT
public immutable PublicKey NODE2_ADDRESS =
    GCN2C4X4ZAUTENP3VYVA3225CUNEAHDKFXDETNRBXZCXUPIJUY64UANT.address;

/// NODE3: GCN3CTOPFFBHZKXUVBZHZN6UFFYFFAZCPJK36U2ZY3L53AL7APM36GYO
public immutable PublicKey NODE3_ADDRESS =
    GCN3CTOPFFBHZKXUVBZHZN6UFFYFFAZCPJK36U2ZY3L53AL7APM36GYO.address;

/// NODE4: GCN4CT336WB6IIKP5CDHWFYFBCNO5BG2Y4777F2QHNA5XUWSUYSQS7IP
public immutable PublicKey NODE4_ADDRESS =
    GCN4CT336WB6IIKP5CDHWFYFBCNO5BG2Y4777F2QHNA5XUWSUYSQS7IP.address;

/// NODE5: GCN5CVXGRUW3B6CJNHUVEJFHXG2WQNMRBQR2RN4TMJ727RF3VM2RA6LF
public immutable PublicKey NODE5_ADDRESS =
    GCN5CVXGRUW3B6CJNHUVEJFHXG2WQNMRBQR2RN4TMJ727RF3VM2RA6LF.address;

/// NODE6: GCN6C3W6DT4TP2BQBFNPDPBP7SK32CJC2ROUUBI4C7Z36TWMK6VZ3CT4
public immutable PublicKey NODE6_ADDRESS =
    GCN6C3W6DT4TP2BQBFNPDPBP7SK32CJC2ROUUBI4C7Z36TWMK6VZ3CT4.address;

/// NODE7: GCN7C7UCTTQQ3RN7Q7AID5ED7VJDN3XPQ6NEAOIMWNA5AWJUFFV5PRBN
public immutable PublicKey NODE7_ADDRESS =
    GCN7C7UCTTQQ3RN7Q7AID5ED7VJDN3XPQ6NEAOIMWNA5AWJUFFV5PRBN.address;

public immutable KeyPair[] genesis_validator_keys = [
    GCN2C4X4ZAUTENP3VYVA3225CUNEAHDKFXDETNRBXZCXUPIJUY64UANT,
    GCN3CTOPFFBHZKXUVBZHZN6UFFYFFAZCPJK36U2ZY3L53AL7APM36GYO,
    GCN4CT336WB6IIKP5CDHWFYFBCNO5BG2Y4777F2QHNA5XUWSUYSQS7IP,
    GCN5CVXGRUW3B6CJNHUVEJFHXG2WQNMRBQR2RN4TMJ727RF3VM2RA6LF,
    GCN6C3W6DT4TP2BQBFNPDPBP7SK32CJC2ROUUBI4C7Z36TWMK6VZ3CT4,
    GCN7C7UCTTQQ3RN7Q7AID5ED7VJDN3XPQ6NEAOIMWNA5AWJUFFV5PRBN
    ];

/// GCOMBBXA6ON7PT7APS4IWS4N53FCBQTLWBPIU4JR2DSOBCA72WEB4XU4:
private immutable GCOMBBXA6ON7PT7APS4IWS4N53FCBQTLWBPIU4JR2DSOBCA72WEB4XU4 =
KeyPair(PublicKey(Point([156, 192, 134, 224, 243, 155, 247, 207, 224, 124, 184, 139, 75, 141, 238, 202, 32, 194, 107,
176, 94, 138, 113, 49, 208, 228, 224, 136, 31, 213, 136, 30])),
SecretKey(Scalar([125, 41, 233, 11, 233, 133, 207, 35, 253, 6, 44, 244, 136, 201, 182, 68, 93, 37, 201, 206, 51, 71,
203, 166, 225, 229, 49, 209, 242, 161, 120, 4])));

/// GDGENYO6TWO6EZG2OXEBVDCNKLHCV2UFLLZY6TJMWTGR23UMJHVHLHKJ:
private immutable GDGENYO6TWO6EZG2OXEBVDCNKLHCV2UFLLZY6TJMWTGR23UMJHVHLHKJ =
KeyPair(PublicKey(Point([204, 70, 225, 222, 157, 157, 226, 100, 218, 117, 200, 26, 140, 77, 82, 206, 42, 234, 133, 90, 243, 143, 77, 44, 180, 205, 29, 110, 140, 73, 234, 117])), SecretKey(Scalar([115, 95, 118, 15, 205, 199, 178, 40, 246, 217, 128, 245, 129, 168, 223, 89, 93, 102, 200, 110, 191, 25, 248, 37, 136, 99, 204, 190, 173, 144, 19, 8])));

/// GCN2C4X4ZAUTENP3VYVA3225CUNEAHDKFXDETNRBXZCXUPIJUY64UANT:
private immutable GCN2C4X4ZAUTENP3VYVA3225CUNEAHDKFXDETNRBXZCXUPIJUY64UANT =
KeyPair(PublicKey(Point([155, 161, 114, 252, 200, 41, 50, 53, 251, 174, 42, 13, 235, 93, 21, 26, 64, 28, 106, 45, 198, 73, 182, 33, 190, 69, 122, 61, 9, 166, 61, 202])), SecretKey(Scalar([164, 206, 34, 110, 32, 193, 201, 0, 110, 132, 233, 30, 33, 37, 73, 99, 25, 205, 114, 100, 147, 33, 17, 118, 197, 178, 165, 234, 3, 222, 99, 15])));

/// GCN3CTOPFFBHZKXUVBZHZN6UFFYFFAZCPJK36U2ZY3L53AL7APM36GYO:
private immutable GCN3CTOPFFBHZKXUVBZHZN6UFFYFFAZCPJK36U2ZY3L53AL7APM36GYO =
KeyPair(PublicKey(Point([155, 177, 77, 207, 41, 66, 124, 170, 244, 168, 114, 124, 183, 212, 41, 112, 82, 131, 34, 122, 85, 191, 83, 89, 198, 215, 221, 129, 127, 3, 217, 191])), SecretKey(Scalar([169, 30, 41, 87, 161, 183, 48, 38, 254, 47, 170, 184, 38, 248, 244, 109, 116, 171, 53, 203, 46, 6, 214, 23, 182, 79, 80, 244, 198, 181, 133, 5])));

/// GCN4CT336WB6IIKP5CDHWFYFBCNO5BG2Y4777F2QHNA5XUWSUYSQS7IP:
private immutable GCN4CT336WB6IIKP5CDHWFYFBCNO5BG2Y4777F2QHNA5XUWSUYSQS7IP =
KeyPair(PublicKey(Point([155, 193, 79, 123, 245, 131, 228, 33, 79, 232, 134, 123, 23, 5, 8, 154, 238, 132, 218, 199, 63, 255, 151, 80, 59, 65, 219, 210, 210, 166, 37, 9])), SecretKey(Scalar([33, 32, 17, 253, 27, 191, 90, 211, 79, 31, 81, 156, 192, 164, 41, 228, 239, 254, 236, 222, 189, 120, 127, 8, 247, 2, 143, 10, 25, 156, 109, 8])));

/// GCN5CVXGRUW3B6CJNHUVEJFHXG2WQNMRBQR2RN4TMJ727RF3VM2RA6LF:
private immutable GCN5CVXGRUW3B6CJNHUVEJFHXG2WQNMRBQR2RN4TMJ727RF3VM2RA6LF =
KeyPair(PublicKey(Point([155, 209, 86, 230, 141, 45, 176, 248, 73, 105, 233, 82, 36, 167, 185, 181, 104, 53, 145, 12, 35, 168, 183, 147, 98, 127, 175, 196, 187, 171, 53, 16])), SecretKey(Scalar([10, 80, 62, 156, 147, 169, 145, 78, 190, 212, 103, 114, 243, 38, 80, 28, 14, 156, 42, 28, 69, 168, 242, 26, 138, 233, 201, 168, 166, 10, 193, 7])));

/// GCN6C3W6DT4TP2BQBFNPDPBP7SK32CJC2ROUUBI4C7Z36TWMK6VZ3CT4:
private immutable GCN6C3W6DT4TP2BQBFNPDPBP7SK32CJC2ROUUBI4C7Z36TWMK6VZ3CT4 =
KeyPair(PublicKey(Point([155, 225, 110, 222, 28, 249, 55, 232, 48, 9, 90, 241, 188, 47, 252, 149, 189, 9, 34, 212, 93, 74, 5, 28, 23, 243, 191, 78, 204, 87, 171, 157])), SecretKey(Scalar([244, 65, 235, 237, 149, 154, 211, 131, 202, 243, 249, 219, 234, 86, 109, 116, 197, 230, 106, 9, 242, 5, 66, 135, 12, 55, 14, 213, 211, 221, 215, 13])));

/// GCN7C7UCTTQQ3RN7Q7AID5ED7VJDN3XPQ6NEAOIMWNA5AWJUFFV5PRBN:
private immutable GCN7C7UCTTQQ3RN7Q7AID5ED7VJDN3XPQ6NEAOIMWNA5AWJUFFV5PRBN =
KeyPair(PublicKey(Point([155, 241, 126, 130, 156, 225, 13, 197, 191, 135, 192, 129, 244, 131, 253, 82, 54, 238, 239, 135, 154, 64, 57, 12, 179, 65, 208, 89, 52, 41, 107, 215])), SecretKey(Scalar([194, 151, 6, 120, 48, 80, 141, 208, 62, 69, 74, 41, 149, 21, 158, 137, 94, 152, 249, 49, 207, 36, 233, 95, 142, 62, 235, 174, 31, 96, 227, 2])));
