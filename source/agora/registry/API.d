/*******************************************************************************

    Definitions of the name registry API

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.registry.API;

import agora.common.Types;
import agora.consensus.data.UTXO;
import agora.crypto.Hash;
import agora.crypto.Key;
import agora.crypto.Schnorr: Signature;

import vibe.http.common;
import vibe.web.rest;

///
public struct RegistryPayloadData
{
    /// the hash of the UTXO that we want to register
    public Hash utxo_key;

    /// the UTXO that we want to register
    public UTXO utxo;

    /// network addresses associated with the public key
    public const(Address)[] addresses;

    /// monotonically increasing sequence number
    public ulong seq;
}

///
public struct RegistryPayload
{
    ///
    public RegistryPayloadData data;

    /// signature over the `data` member
    public Signature signature;

    ///
    public void signPayload (in KeyPair kp) nothrow
    {
        this.signature = kp.sign(hashFull(this.data)[]);
    }

    ///
    public bool verifySignature (in PublicKey public_key) const nothrow @nogc @safe
    {
        return public_key.verify(this.signature, hashFull(this.data)[]);
    }
}

/// API allowing to store network addresses under a public key
public interface NameRegistryAPI
{
    @safe:

    /***************************************************************************

        Get network addresses corresponding to a public key

        Params:
            key = the key that was used to register the network addresses

        Returns:
            Network addresses associated with the `public_key`

        API:
            GET /validator

    ***************************************************************************/

    public const(RegistryPayload) getValidator (Hash hash);

    /***************************************************************************

        Register network addresses corresponding to a public key

        Params:
            registry_payload =
                the data we want to register with the name registry server

        Returns:
            empty string, if the registration was successful, otherwise returns
            the error message

        API:
            PUT /validator

    ***************************************************************************/

    public void putValidator (RegistryPayload registry_payload);
}
