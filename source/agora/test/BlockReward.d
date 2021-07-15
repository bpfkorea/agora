/*******************************************************************************

    Contains tests for block reward distribution

    Copyright:
        Copyright (c) 2021 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.BlockReward;

import agora.consensus.data.Transaction;
import agora.common.Amount;
import agora.common.Config;
import agora.common.ManagedDatabase;
import agora.consensus.EnrollmentManager;
import agora.consensus.data.PreImageInfo;
import agora.consensus.state.UTXOSet;
import agora.consensus.data.genesis.Test;
import agora.crypto.Key;
import agora.test.Base;
import agora.utils.WellKnownKeys;

import core.atomic;

// This derived `EnrollmentManager` does not reveal any preimages
// after enrollment.
version (unittest)
package class MissingPreImageEM : EnrollmentManager
{
    private shared bool* reveal_preimage;
    private int[] no_reveal_preimage_arr;

    ///
    public this (Parameters!(EnrollmentManager.__ctor) args,
        shared(bool)* reveal_preimage, int[] no_reveal_preimage_arr)
    {
        assert(reveal_preimage !is null);
        this.reveal_preimage = reveal_preimage;
        this.no_reveal_preimage_arr = no_reveal_preimage_arr;
        super(args);
    }

    /// This does not reveal pre-images intentionally
    public override bool getNextPreimage (out PreImageInfo preimage, in Height height) @safe
    {
        if (!atomicLoad(*this.reveal_preimage) || no_reveal_preimage_arr.canFind(height + this.PreimageRevealPeriod))
            return false;

        return super.getNextPreimage(preimage, height);
    }
}

// This derived TestValidatorNode does not reveal any preimages using the
// `MissingPreImageEM` class
version (unittest)
package class NoPreImageVN : TestValidatorNode
{
    private shared bool* reveal_preimage;
    private int[] no_reveal_preimage_arr;
    private uint preimage_reveal_period;

    ///
    public this (Parameters!(TestValidatorNode.__ctor) args,
        shared(bool)* reveal_preimage, int[] no_reveal_preimage_arr,
        uint preimage_reveal_period)
    {
        this.reveal_preimage = reveal_preimage;
        this.no_reveal_preimage_arr = no_reveal_preimage_arr;
        this.preimage_reveal_period = preimage_reveal_period;
        super(args);
    }

    ///
    protected override EnrollmentManager makeEnrollmentManager ()
    {
        return new MissingPreImageEM(this.stateDB, this.cacheDB,
            this.config.validator.key_pair, this.params, preimage_reveal_period, this.reveal_preimage,
            this.no_reveal_preimage_arr);
    }
}

version (unittest)
package class MissingPreimageAPIManager(int[] missing_preimage_validator_idxs,
    int[] no_reveal_preimage_arr, uint preimage_reveal_period) : TestAPIManager
{
    public static shared bool reveal_preimage = false;

    ///
    mixin ForwardCtor!();

    ///
    public override void createNewNode (Config conf, string file, int line)
    {
        if (missing_preimage_validator_idxs.canFind(this.nodes.length))
            this.addNewNode!NoPreImageVN(conf, &reveal_preimage, no_reveal_preimage_arr, preimage_reveal_period, file, line);
        else
            super.createNewNode(conf, file, line);
    }
}

version (unittest)
mixin template CreateAndExpectNewBlockDef()
{
    void createAndExpectNewBlock (Height new_block_height)
    {
        Transaction[] txs;

        // create enough tx's for a single block
        txs = blocks[new_block_height - 1].spendable().map!(txb => txb
            .sign()).array();

        // send it to one node
        txs.each!(tx => node1.putTransaction(tx));

        network.expectHeight(new_block_height);

        // add next block
        blocks ~= node1.getBlocksFrom(new_block_height, 1);

        auto cb_txs = blocks[$-1].txs.filter!(tx => tx.isCoinbase())
            .array;

        // regular block
        immutable block_height = blocks[$-1].header.height;
        if ((block_height < conf.block_reward_delay + conf.block_reward_gap) ||
            ((block_height - conf.block_reward_delay) % conf.block_reward_gap))
            assert(cb_txs.length == 0);
        else
        {
            // payout block
            assert(cb_txs.length == 1);
            assert(cb_txs[0].outputs.length == payout_cb_output_length);
            foreach (ref output; cb_txs[0].outputs)
                assert(output.value == payout_cb_validator_amounts[PublicKey(output.lock.bytes)], output.value.toString());
        }
    }
}

// no missing preimages, no missing signatures
unittest
{
    TestConf conf = {
        quorum_threshold : 100,
        block_reward_gap: 5,
        block_reward_delay: 2,
        block_interval_sec: 1,
    };
    auto network = makeTestNetwork!TestAPIManager(conf);
    network.start();
    scope(exit) network.shutdown();
    scope(failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node1 = nodes[0];
    auto blocks = node1.getBlocksFrom(0, 2);

    // expectations
    ulong payout_cb_output_length = 1 + GenesisBlock.header.enrollments.length;
    Amount[PublicKey] payout_cb_validator_amounts;
    foreach (ind; 0 .. nodes.length)
        payout_cb_validator_amounts[nodes[ind].getPublicKey(PublicKey.init).key] = Amount(4_5000000);
    payout_cb_validator_amounts[CommonsBudget.address] = Amount(50_0000000);

    mixin CreateAndExpectNewBlockDef;

    // create GenesisValidatorCycle - 1 blocks
    foreach (block_idx; 1 .. GenesisValidatorCycle)
    {
        createAndExpectNewBlock(Height(block_idx));
    }
}

// One of the validators doesn't send preimages, and also doesn't sign
// for 3 out of the 5 blocks. The total number of signatures on blocks
// [1 .. 5] will be 96.43% of the signature count of the best case scenario
// (all validators sign all blocks). Total validator block reward will be
// decreased exponentially to 85% of the reward for best case scenario
// (all validators sign all blocks).
unittest
{
    import core.atomic : atomicStore;

    TestConf conf = {
        quorum_threshold : 80,
        block_reward_gap: 5,
        block_reward_delay: 2,
        recurring_enrollment : false,
        block_interval_sec: 1,
    };
    auto network = makeTestNetwork!(MissingPreimageAPIManager!([5],[3,4,5,6,7], 2))(conf);
    atomicStore(network.reveal_preimage, true);
    network.start();
    scope(exit) network.shutdown();
    scope(failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node1 = nodes[0];
    auto blocks = node1.getBlocksFrom(0, 2);

    // expectations
    ulong payout_cb_output_length = 1 + GenesisBlock.header.enrollments.length;
    Amount[PublicKey] payout_cb_validator_amounts =
    [
        CommonsBudget.address: Amount(54_0500000),
        nodes[0].getPublicKey(PublicKey.init).key: Amount(42500000),
        nodes[1].getPublicKey(PublicKey.init).key: Amount(42500000),
        nodes[2].getPublicKey(PublicKey.init).key: Amount(42500000),
        nodes[3].getPublicKey(PublicKey.init).key: Amount(42500000),
        nodes[4].getPublicKey(PublicKey.init).key: Amount(42500000),
        // slashed validator still gets rewarded for the block for which he shared
        // his preimage, and also signed(block 1 and 2); but not for subsequent blocks
        nodes[5].getPublicKey(PublicKey.init).key: Amount(17000000),
    ];

    mixin CreateAndExpectNewBlockDef;

    foreach (block_idx; 1 .. 8)
    {
        createAndExpectNewBlock(Height(block_idx));
    }
}
