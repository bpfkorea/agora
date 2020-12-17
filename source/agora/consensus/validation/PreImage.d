/*******************************************************************************

    Contains validation routines for pre-image

    Copyright:
        Copyright (c) 2019-2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.validation.PreImage;

import agora.common.Hash;
import agora.consensus.data.Params;
import agora.consensus.data.PreImageInfo;

version (unittest)
{
    import agora.common.crypto.ECC;
    import agora.consensus.data.Enrollment;

    import std.algorithm.mutation : reverse;
}

/*******************************************************************************

    Check the validity of a new pre-image information

    Pre-image infomation is considered valid if:
        - The keys for enrollment in two pieces of pre-image information are
            same
        - Height for a pre-image is greater than height for a current image
        - A current image is same as n times hashed value of a pre-image
            (n = difference of two heights).

    Params:
        new_image = The pre-image information to check
        prev_image = The previous pre-image information
        validator_cycle = The defined period as a validator

    Returns:
        `null` if the pre-image is valid, otherwise a string
        explaining the reason it is invalid.

*******************************************************************************/

public string isInvalidReason (const ref PreImageInfo new_image,
    const ref PreImageInfo prev_image, uint validator_cycle) nothrow @safe
{
    if (new_image.enroll_key != prev_image.enroll_key)
        return "The pre-image's enrollment key differs from its descendant";

    if (new_image.distance <= prev_image.distance)
        return "The height of new pre-image is not greater than that of the previous one";

    if (new_image.distance > validator_cycle)
        return "The hashing count of two pre-images is above the validator cycle";

    Hash temp_hash = new_image.hash;
    foreach (_; prev_image.distance .. new_image.distance)
        temp_hash = hashFull(temp_hash);
    if (temp_hash != prev_image.hash)
        return "The pre-image has a invalid hash value";

    return null;
}

/// Ditto but returns `bool`, only usable in unittests
version (unittest)
public bool isValid (const ref PreImageInfo prev_image,
    const ref PreImageInfo new_image, uint validator_cycle) nothrow @safe
{
    return isInvalidReason(prev_image, new_image, validator_cycle) is null;
}

/// test for validity of pre-image
unittest
{
    Hash[] preimages;
    preimages ~= hashFull(Scalar.random());
    foreach (i; 0 .. 1007)
        preimages ~= hashFull(preimages[i]);
    reverse(preimages);

    PreImageInfo prev_image = PreImageInfo(hashFull("abc"), preimages[0], 1);
    auto params = new immutable(ConsensusParams)(1008);

    // valid pre-image
    PreImageInfo new_image = PreImageInfo(hashFull("abc"), preimages[100], 101);
    assert(new_image.isValid(prev_image, params.ValidatorCycle));

    // invalid pre-image with wrong enrollment key
    new_image = PreImageInfo(hashFull("xyz"), preimages[100], 101);
    assert(!new_image.isValid(prev_image, params.ValidatorCycle));

    // invalid pre-image with wrong height number
    new_image = PreImageInfo(hashFull("abc"), preimages[1], 3);
    assert(!new_image.isValid(prev_image, params.ValidatorCycle));

    // invalid pre-image with wrong hash value
    new_image = PreImageInfo(hashFull("abc"), preimages[100], 100);
    assert(!new_image.isValid(prev_image, params.ValidatorCycle));
}
