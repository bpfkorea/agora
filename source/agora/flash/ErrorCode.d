/*******************************************************************************

    Contains error codes for the Flash API.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.ErrorCode;

/// Lists possible error codes for the API calls.
public enum ErrorCode : ushort
{
    /// No error.
    None = 0,

    /// Unknown error
    Unknown,

    /// This Flash node does not manage this public key
    KeyNotRecognized,

    /// Cannot find this node in the flash node registry
    AddressNotFound,

    /// Couldn't find a path to another node, or it was too long
    PathNotFound,

    /// The Listener rejected opening this channel
    UserRejectedChannel,

    /// Updates with the same balance will be rejected
    UpdateRejected,

    /// The forwarding amount is too small compared to the payload
    AmountTooSmall,

    /// The forwarding lock is too large compared to the payload
    LockTooLarge,

    /// A payment / update proposal is already in progress. If both parties
    /// issue a request towards each other at the same time, only one of the
    /// requests can be accepted. The node with priority will have its request
    /// proceed, while the other request will be rescheduled for later.
    /// The nodes use alternating priorities based on the sequence ID,
    /// e.g. [seq 1: N1, seq2: N2, seq 3: N1, seq 4: N2, ...]
    ProposalInProgress,

    /// Requested an update transaction before the matching settlement was signed.
    SettleNotReceived,

    /// Settlement signature not signed yet
    SettleNotSigned,

    /// Update signature not signed yet
    UpdateNotSigned,

    /// This sequence ID was not agreed upon, or it's outdated.
    InvalidSequenceID,

    /// Signature is invalid.
    InvalidSignature,

    /// Channel ID does not exist / unknown.
    InvalidChannelID,

    /// Channel ID exists but the channel is not open.
    ChannelNotOpen,

    /// Channel ID exists but it's not closing / closed.
    ChannelNotClosing,

    /// Tried to create a new channel ID with the same ID as an existing channel ID.
    DuplicateChannelID,

    /// Mismatching genesis hash. E.g. if one node is running on TestNet and the
    /// other on CoinNet.
    InvalidGenesisHash,

    /// Counter-party disagrees with the funding amount for this channel.
    /// The message in the `Result` may have the node's specific reasoning
    /// as to the minimum funding limits of the node.
    RejectedFundingAmount,

    /// Counter-party disagrees with the settle time. The message in the
    /// `Result` may have the node's specific reasoning.
    RejectedSettleTime,

    /// The receiving node rejects routing this payment as it exceeds its
    /// current balance or its comfortable maximum payment amount it's willing
    /// to ever route through this channel
    ExceedsMaximumPayment,

    /// A new balance update request cannot be made until the active signing
    /// process is complete.
    SigningInProcess,

    /// The new balance request has been rejected, e.g. trying to spend more
    /// than allocated in the funding transaction.
    RejectedBalanceRequest,

    /// Cannot decrypt the payload, or the packet contains invalid data
    InvalidOnionPacket,

    /// The two counter-parties have mismatching block height information,
    /// which means one of the two nodes is out of sync with the blockchain.
    MismatchingBlockHeight,

    /// Receiving node implements a different version of the Onion protocol
    VersionMismatch,

    /// Either funding UTXO does not belong to the given PublicKey or does not
    /// have enough funds
    RejectedFundingUTXO,

    /// Too much fee request for closing TX
    RejectedClosingFee,
}
