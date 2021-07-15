/*******************************************************************************

    The set for consensus-critical constants

    This defines the class for the consensus-critical constants. Only one
    object should exist for a single node. The `class` is `immutable`, hence
    the constants need to be set at the start of the process. The
    consensus-critical constants are the protocol-level constants, so they
    shouldn't be modified outside of test environments.

    Adding_a_new_value:
    Values can be added to `ConsensusParams` when they represent constants
    that are consensus-critical (changing them would break consensus).
    An example of such a consensus-critical constant is the hash of the genesis
    block, or the minimum time interval between blocks.
    On the other hand, values that can differ between nodes without breaking
    consensus should go in the node's configuration. This includes, for example,
    the timeout a node will apply to its requests.

    ConsensusParams_or_ConsensusConfig:
    `ConsensusParams` also includes a `ConsensusConfig` struct. The goal of this
    structure is to contain the values that can be tweaked between networks.
    One example of such a tweak is to provide a different genesis block between
    MainNet and TestNet. `ConsensusConfig` is used extensively to allow
    in-memory testing without inducing too much overhead (e.g. by reducing the
    value of `validator_cycle` to 20).
    By default, new additions should go to `ConsensusParams`, and only be moved
    to `ConsensusConfig` if a need for it arises.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.Params;

import agora.common.Amount;
import agora.consensus.data.Block;
import agora.consensus.Reward;
import agora.crypto.Key;

import core.time;

/// Ditto
public immutable class ConsensusParams
{
    /// The Genesis block of the chain
    public Block Genesis;

    /// How often blocks should be created
    public Duration BlockInterval;

    /// The address of commons budget
    public PublicKey CommonsBudgetAddress;

    /// Underlying data
    private ConsensusConfig data;

    /// The amount of a penalty for slashed validators
    public Amount SlashPenaltyAmount = 10_000.coins;

    mixin ROProperty!("ValidatorCycle", "validator_cycle");
    mixin ROProperty!("MaxQuorumNodes", "max_quorum_nodes");
    mixin ROProperty!("QuorumThreshold", "quorum_threshold");
    mixin ROProperty!("QuorumShuffleInterval", "quorum_shuffle_interval");
    mixin ROProperty!("TxPayloadMaxSize", "tx_payload_max_size");
    mixin ROProperty!("TxPayloadFeeFactor", "tx_payload_fee_factor");
    mixin ROProperty!("ValidatorTXFeeCut", "validator_tx_fee_cut");
    mixin ROProperty!("PayoutPeriod", "payout_period");
    mixin ROProperty!("GenesisTimestamp", "genesis_timestamp");
    mixin ROProperty!("MinFee", "min_fee");
    mixin ROProperty!("BlockRewardFactorA", "block_reward_factor_a");
    mixin ROProperty!("BlockRewardFactorB", "block_reward_factor_b");
    mixin ROProperty!("BlockRewardFactorC", "block_reward_factor_c");
    mixin ROProperty!("BlockRewardGap", "block_reward_gap");
    mixin ROProperty!("BlockRewardDelay", "block_reward_delay");
    mixin ROProperty!("ValidatorBlockRewards", "validator_block_rewards");
    mixin ROProperty!("FoundationBlockRewards", "foundation_block_rewards");

    /***************************************************************************

        Constructor

        Params:
            genesis = Genesis block to use for this chain
            commons_budget_address = Address of the 'Commons' budget
            config = The (potentially) user-configured consensus parameters
            block_interval = How often blocks are expected to be created

    ***************************************************************************/

    public this (immutable(Block) genesis,
                 in PublicKey commons_budget_address,
                 ConsensusConfig config = ConsensusConfig.init,
                 Duration block_interval = 1.seconds) @safe pure nothrow
    {
        this.Genesis = genesis;
        this.CommonsBudgetAddress = commons_budget_address,
        this.BlockInterval = block_interval;

        if (!config.validator_block_rewards.length)
            config.validator_block_rewards = ConsensusConfig.DefaultValidatorBlockRewards;
        this.data = config;
    }

    /// Default for unittest, uses the test genesis block
    version (unittest) public this (
        uint validator_cycle = 20, uint max_quorum_nodes = 7,
        uint quorum_threshold = 80, Amount min_fee = 0) @safe pure nothrow
    {
        import agora.consensus.data.genesis.Test : GenesisBlock;
        import agora.utils.WellKnownKeys;
        ConsensusConfig config = {
            validator_cycle: validator_cycle,
            max_quorum_nodes: max_quorum_nodes,
            quorum_threshold: quorum_threshold,
            min_fee: min_fee,
            validator_block_rewards: ConsensusConfig.DefaultValidatorBlockRewards,
        };
        this(GenesisBlock, CommonsBudget.address, config);
    }
}

/// Ditto
public struct ConsensusConfig
{
    public ulong genesis_timestamp = 1609459200; // 2021-01-01:00:00:00 GMT

    /// The cycle length for a validator
    public uint validator_cycle = 1008;

    /// Maximum number of nodes to include in an autogenerated quorum set
    public uint max_quorum_nodes = 7;

    /// Threshold to use in the autogenerated quorum. Between 1 and 100.
    public uint quorum_threshold = 80;

    /// The maximum number of blocks before a quorum shuffle takes place.
    /// Note that a shuffle may occur before the cycle ends if the active
    /// validator set changes (new enrollments, expired enrollments..)
    public uint quorum_shuffle_interval = 30;

    /// The maximum size of data payload
    public uint tx_payload_max_size = 1024;

    /// The factor to calculate for the fee of data payload
    public uint tx_payload_fee_factor = 200;

    /// The share that Validators would get out of the transction fees (Out of 100)
    /// The rest would go to the Commons Budget
    public ubyte validator_tx_fee_cut = 70;

    /// How frequent the payments to Validators will be in blocks
    public uint payout_period = 144;

    /// The minimum (transaction size adjusted) fee.
    /// Transaction size adjusted fee = tx fee / tx size in bytes.
    public Amount min_fee = Amount(700);

    /// The number of blocks between 2 block reward payout
    /// The value of 3 means block reward payout happens at the block 1, 4, 7...
    public ushort block_reward_gap = 10;

    /// factor 'a' in the block reward reduction function of f(x) = b*e^(a*x) + c
    public double block_reward_factor_a = 0.046;

    /// factor 'b' in the block reward reduction function of f(x) = b*e^(a*x) + c
    public double block_reward_factor_b = 1;

    /// factor 'c' in the block reward reduction function of f(x) = b*e^(a*x) + c
    public double block_reward_factor_c = 1;

    /// The delay (measured in blocks) after which block reward is payed
    /// The value of 5 means the block reward payout for confirming blocks
    /// [(X-confirmation_payout_gap + 1), (X)] happens at block (X + block_reward_delay)
    public ushort block_reward_delay = 5;

    /// Block rewards given to the validators for 128 years
    public immutable(BlockRewardsTup)[] validator_block_rewards;

    /// Block rewards given to the foundation for roughly 6 years
    public immutable(BlockRewardsTup)[] foundation_block_rewards =
    [
         mbr(315_360_000_0000000), mbr(315_360_000_0000000), mbr(315_360_000_0000000),
         mbr(315_360_000_0000000), mbr(315_360_000_0000000), mbr(223_200_000_0000000, 22_320_000)
    ];

    /// Default block rewards given to validators
    /// Not assigned directly to `validator_block_rewards` here to avoid
    /// 'cannot inline default argument' compiler error
    private static immutable BlockRewardsTup[] DefaultValidatorBlockRewards =
    [
        mbr(170_294_400_0000000), mbr(159_548_823_0000000), mbr(149_481_293_0000000), mbr(140_049_023_0000000),
        mbr(131_211_930_0000000), mbr(122_932_457_0000000), mbr(115_175_419_0000000), mbr(107_907_850_0000000),
        mbr(101_098_865_0000000), mbr(94_719_526_0000000), mbr(88_742_724_0000000), mbr(83_143_058_0000000),
        mbr(77_896_731_0000000), mbr(72_981_448_0000000), mbr(68_376_318_0000000), mbr(64_061_773_0000000),
        mbr(60_019_475_0000000), mbr(56_232_246_0000000), mbr(52_683_991_0000000), mbr(49_359_631_0000000),
        mbr(46_245_039_0000000), mbr(43_326_977_0000000), mbr(40_593_044_0000000), mbr(38_031_623_0000000),
        mbr(35_631_828_0000000), mbr(33_383_460_0000000), mbr(31_276_963_0000000), mbr(29_303_387_0000000),
        mbr(27_454_343_0000000), mbr(25_721_974_0000000), mbr(24_098_918_0000000), mbr(22_578_276_0000000),
        mbr(21_153_587_0000000), mbr(19_818_795_0000000), mbr(18_568_229_0000000), mbr(17_396_574_0000000),
        mbr(16_298_850_0000000), mbr(15_270_393_0000000), mbr(14_306_831_0000000), mbr(13_404_070_0000000),
        mbr(12_558_273_0000000), mbr(11_765_846_0000000), mbr(11_023_421_0000000), mbr(10_327_843_0000000),
        mbr(9_676_156_0000000), mbr(9_065_591_0000000), mbr(8_493_552_0000000), mbr(7_957_609_0000000),
        mbr(7_455_484_0000000), mbr(6_985_043_0000000), mbr(6_544_287_0000000), mbr(6_131_342_0000000),
        mbr(5_744_454_0000000), mbr(5_381_979_0000000), mbr(5_042_376_0000000), mbr(4_724_203_0000000),
        mbr(4_426_105_0000000), mbr(4_146_818_0000000), mbr(3_885_154_0000000), mbr(3_640_001_0000000),
        mbr(3_410_317_0000000), mbr(3_195_126_0000000), mbr(2_993_513_0000000), mbr(2_804_623_0000000),
        mbr(2_627_651_0000000), mbr(2_461_846_0000000), mbr(2_306_504_0000000), mbr(2_160_963_0000000),
        mbr(2_024_606_0000000), mbr(1_896_854_0000000), mbr(1_777_162_0000000), mbr(1_665_023_0000000),
        mbr(1_559_960_0000000), mbr(1_461_527_0000000), mbr(1_369_305_0000000), mbr(1_282_901_0000000),
        mbr(1_201_950_0000000), mbr(1_126_107_0000000), mbr(1_055_050_0000000), mbr(988_476_0000000),
        mbr(926_103_0000000), mbr(867_666_0000000), mbr(812_917_0000000), mbr(761_622_0000000), mbr(713_563_0000000),
        mbr(668_537_0000000), mbr(626_353_0000000), mbr(586_830_0000000), mbr(549_801_0000000), mbr(515_108_0000000),
        mbr(482_605_0000000), mbr(452_153_0000000), mbr(423_622_0000000), mbr(396_891_0000000), mbr(371_847_0000000),
        mbr(348_384_0000000), mbr(326_401_0000000), mbr(305_805_0000000), mbr(286_509_0000000), mbr(268_430_0000000),
        mbr(251_492_0000000), mbr(235_623_0000000), mbr(220_755_0000000), mbr(206_825_0000000), mbr(193_775_0000000),
        mbr(181_548_0000000), mbr(170_092_0000000), mbr(159_359_0000000), mbr(149_304_0000000), mbr(139_883_0000000),
        mbr(131_056_0000000), mbr(122_786_0000000), mbr(115_038_0000000), mbr(107_780_0000000), mbr(100_979_0000000),
        mbr(94_607_0000000), mbr(88_637_0000000), mbr(83_044_0000000), mbr(77_804_0000000), mbr(72_895_0000000),
        mbr(68_295_0000000), mbr(63_986_0000000), mbr(59_948_0000000), mbr(56_165_0000000), mbr(52_621_0000000),
        mbr(49_301_0000000), mbr(46_190_0000000), mbr(43_275_0000000)
    ];
}

/// Inserts properties functions aliasing `ConsensusConfig`
private mixin template ROProperty (string to, string from)
{
    mixin (
        "public typeof(this.data.", from, ") ", to,
        " () @safe pure nothrow @nogc { return this.data.", from, "; }");
}
