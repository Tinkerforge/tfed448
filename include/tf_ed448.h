#ifndef TF_ED448_H
#define TF_ED448_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TF_ED448_PRIVATE_SEED_SIZE 57
#define TF_ED448_PUBLIC_KEY_SIZE 57
#define TF_ED448_SIGNATURE_SIZE 114

enum {
    TF_ED448_SUCCESS = 0,
    TF_ED448_INVALID_ARGUMENT = -1,
    TF_ED448_PUBLIC_KEY_MISMATCH = -2,
    TF_ED448_INVALID_PUBLIC_KEY = -3,
    TF_ED448_INVALID_SIGNATURE = -4,
    TF_ED448_OUT_OF_MEMORY = -5,
};

int tf_ed448_derive_public(
    const uint8_t *private_seed,
    size_t private_seed_len,
    uint8_t *public_key,
    size_t public_key_len);

int tf_ed448_validate_public(
    const uint8_t *public_key,
    size_t public_key_len);

int tf_ed448_sign(
    const uint8_t *private_seed,
    size_t private_seed_len,
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *signature,
    size_t signature_len);

int tf_ed448_verify(
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len);

int tf_shake256(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len);

#ifdef __cplusplus
}
#endif

#endif
