/*******************************************************************************

    Contains the simplest empty block creating test

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.EmptyBlocks;

version (unittest):

import agora.api.Validator;
import agora.consensus.data.Transaction;
import agora.test.Base;

/// EmptyBlocks test
unittest
{
    auto network = makeTestNetwork!TestAPIManager(TestConf.init);
    network.start();
    scope(exit) network.shutdown();
    scope(failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];

    // Create blocks for 2 validator cycles and a couple more
    auto target_height = Height(2 * GenesisValidatorCycle + 2);
    network.generateBlocks(target_height, true);
    network.assertSameBlocks(target_height);

    auto blocks = node_1.getBlocksFrom(Height(1), cast(uint)target_height);
    blocks.each!(block => assert(block.txs.all!(tx => tx.isCoinbase)));
}
