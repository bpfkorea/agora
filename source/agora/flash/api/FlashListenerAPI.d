/*******************************************************************************

    Contains the Flash API.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.api.FlashListenerAPI;

import agora.common.Types;
import agora.common.Amount;
import agora.crypto.Key;
import agora.consensus.data.UTXO;
import agora.flash.Config;
import agora.flash.ErrorCode;
import agora.flash.Invoice;
import agora.flash.Types;

import vibe.data.serialization;
import vibe.http.common;
import vibe.web.rest;

///
struct FeeUTXOs
{
    /// UTXO hashes
    Hash[] utxos;

    /// Total value stored in `utxos`
    Amount total_value;
}

/// This is the API that each Flash listener must implement, for example wallets
/// or other front-ends to Agora.
@path("/")
@serializationPolicy!(Base64ArrayPolicy)
public interface FlashListenerAPI
{
@safe:
    /***************************************************************************

        Called when the state of a channel changes, for example when the
        channel is accepted / rejected by the counter-party.

        Params:
            chan_id = channel ID
            state = the current state of the channel
            error = if state is rejected, it will contain any error stating the
                reason why a channel was rejected

    ***************************************************************************/

    public void onChannelNotify (PublicKey pk, Hash chan_id, ChannelState state,
        ErrorCode error);

    /***************************************************************************

        Called when a counter-party has requested opening a channel
        with this node. The wallet should return an empty string if it
        accepts opening this channel, or an error message if the
        channel should be rejected.

        Params:
            chan_conf = the channel configuration

        Returns:
            an empty string if the channel open should be accepted,
            else an error message which will be propagated back to the
            counter-party

    ***************************************************************************/

    public string onRequestedChannelOpen (PublicKey pk, ChannelConfig chan_conf);

    /***************************************************************************

        Called when the payment for the given invoice has been successful.

        Params:
            invoice = the invoice that was paid

    ***************************************************************************/

    public void onPaymentSuccess (PublicKey pk, Invoice invoice);

    /***************************************************************************

        Called when the payment for the given invoice has failed.
        The payment can be retried again with the `payInvoice()` Flash API.

        Params:
            invoice = the invoice that was paid

    ***************************************************************************/

    public void onPaymentFailure (PublicKey pk, Invoice invoice, ErrorCode error);

    /***************************************************************************

        Try to get a set of UTXOs enough to cover `amount`

        Params:
            pk = public key
            amount = desired total value of the UTXOs

        Returns:
            set of UTXOs to cover `amount`, on best effort basis

    ***************************************************************************/

    public FeeUTXOs getFeeUTXOs (PublicKey pk, Amount amount);


    /***************************************************************************

        Returns:
            Appropriate amount of fees per byte

    ***************************************************************************/

    public Amount getEstimatedTxFee ();
}
