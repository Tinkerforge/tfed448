#include "tf_ed448.h"

#include <decaf/ed448.h>

static int message_is_valid(const uint8_t *message, size_t message_len)
{
    return message != NULL || message_len == 0;
}

static const uint8_t empty_message;

static const uint8_t *nonnull_message(const uint8_t *message)
{
    return message != NULL ? message : &empty_message;
}

static int point_is_valid_non_identity(
    const uint8_t encoded[TF_ED448_PUBLIC_KEY_SIZE])
{
    decaf_448_point_t point;
    int valid = decaf_448_point_decode_like_eddsa_and_mul_by_ratio(point, encoded) ==
                    DECAF_SUCCESS &&
                decaf_448_point_eq(point, decaf_448_point_identity) != DECAF_TRUE;

    decaf_448_point_destroy(point);
    return valid;
}

int tf_ed448_derive_public(
    const uint8_t *private_seed,
    size_t private_seed_len,
    uint8_t *public_key,
    size_t public_key_len)
{
    if (private_seed == NULL || private_seed_len != TF_ED448_PRIVATE_SEED_SIZE ||
        public_key == NULL || public_key_len != TF_ED448_PUBLIC_KEY_SIZE) {
        return TF_ED448_INVALID_ARGUMENT;
    }

    decaf_ed448_derive_public_key(public_key, private_seed);
    return TF_ED448_SUCCESS;
}

int tf_ed448_validate_public(
    const uint8_t *public_key,
    size_t public_key_len)
{
    if (public_key == NULL || public_key_len != TF_ED448_PUBLIC_KEY_SIZE) {
        return TF_ED448_INVALID_ARGUMENT;
    }

    return point_is_valid_non_identity(public_key)
               ? TF_ED448_SUCCESS
               : TF_ED448_INVALID_PUBLIC_KEY;
}

int tf_ed448_sign(
    const uint8_t *private_seed,
    size_t private_seed_len,
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *signature,
    size_t signature_len)
{
    decaf_eddsa_448_keypair_t keypair;
    int result = TF_ED448_SUCCESS;

    if (private_seed == NULL || private_seed_len != TF_ED448_PRIVATE_SEED_SIZE ||
        public_key == NULL || public_key_len != TF_ED448_PUBLIC_KEY_SIZE ||
        signature == NULL || signature_len != TF_ED448_SIGNATURE_SIZE ||
        !message_is_valid(message, message_len)) {
        return TF_ED448_INVALID_ARGUMENT;
    }

    decaf_ed448_derive_keypair(keypair, private_seed);
    if (decaf_memeq(keypair->pubkey, public_key, TF_ED448_PUBLIC_KEY_SIZE) !=
        DECAF_TRUE) {
        result = TF_ED448_PUBLIC_KEY_MISMATCH;
    } else {
        decaf_ed448_keypair_sign(
            signature, keypair, nonnull_message(message), message_len, 0, NULL, 0);
    }

    decaf_ed448_keypair_destroy(keypair);
    return result;
}

int tf_ed448_verify(
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len)
{
    if (public_key == NULL || public_key_len != TF_ED448_PUBLIC_KEY_SIZE ||
        signature == NULL || signature_len != TF_ED448_SIGNATURE_SIZE ||
        !message_is_valid(message, message_len)) {
        return TF_ED448_INVALID_ARGUMENT;
    }

    if (tf_ed448_validate_public(public_key, public_key_len) != TF_ED448_SUCCESS) {
        return TF_ED448_INVALID_PUBLIC_KEY;
    }

    if (!point_is_valid_non_identity(signature)) {
        return TF_ED448_INVALID_SIGNATURE;
    }

    decaf_error_t result = decaf_ed448_verify(
        signature, public_key, nonnull_message(message), message_len, 0, NULL, 0);
    if (result == (decaf_error_t)1) {
        return TF_ED448_OUT_OF_MEMORY;
    }
    if (result != DECAF_SUCCESS) {
        return TF_ED448_INVALID_SIGNATURE;
    }

    return TF_ED448_SUCCESS;
}

int tf_shake256(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len)
{
    if (!message_is_valid(input, input_len) ||
        (output == NULL && output_len != 0)) {
        return TF_ED448_INVALID_ARGUMENT;
    }

    decaf_shake256_hash(
        output_len != 0 ? output : (uint8_t *)&empty_message,
        output_len,
        nonnull_message(input),
        input_len);
    return TF_ED448_SUCCESS;
}
