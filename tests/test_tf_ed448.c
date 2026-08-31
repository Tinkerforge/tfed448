#include "tf_ed448.h"

#include <stdio.h>
#include <string.h>

static const uint8_t private_seed[TF_ED448_PRIVATE_SEED_SIZE] = {
    0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10,
    0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e, 0xbf,
    0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa, 0x8c, 0x9f,
    0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3, 0x48, 0xa3,
    0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e,
    0x39, 0xa3, 0xfc, 0x5b, 0x94, 0x49, 0x2f, 0x8f,
    0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9,
    0x5b,
};

static const uint8_t public_key[TF_ED448_PUBLIC_KEY_SIZE] = {
    0x5f, 0xd7, 0x44, 0x9b, 0x59, 0xb4, 0x61, 0xfd,
    0x2c, 0xe7, 0x87, 0xec, 0x61, 0x6a, 0xd4, 0x6a,
    0x1d, 0xa1, 0x34, 0x24, 0x85, 0xa7, 0x0e, 0x1f,
    0x8a, 0x0e, 0xa7, 0x5d, 0x80, 0xe9, 0x67, 0x78,
    0xed, 0xf1, 0x24, 0x76, 0x9b, 0x46, 0xc7, 0x06,
    0x1b, 0xd6, 0x78, 0x3d, 0xf1, 0xe5, 0x0f, 0x6c,
    0xd1, 0xfa, 0x1a, 0xbe, 0xaf, 0xe8, 0x25, 0x61,
    0x80,
};

static const uint8_t signature[TF_ED448_SIGNATURE_SIZE] = {
    0x53, 0x3a, 0x37, 0xf6, 0xbb, 0xe4, 0x57, 0x25,
    0x1f, 0x02, 0x3c, 0x0d, 0x88, 0xf9, 0x76, 0xae,
    0x2d, 0xfb, 0x50, 0x4a, 0x84, 0x3e, 0x34, 0xd2,
    0x07, 0x4f, 0xd8, 0x23, 0xd4, 0x1a, 0x59, 0x1f,
    0x2b, 0x23, 0x3f, 0x03, 0x4f, 0x62, 0x82, 0x81,
    0xf2, 0xfd, 0x7a, 0x22, 0xdd, 0xd4, 0x7d, 0x78,
    0x28, 0xc5, 0x9b, 0xd0, 0xa2, 0x1b, 0xfd, 0x39,
    0x80, 0xff, 0x0d, 0x20, 0x28, 0xd4, 0xb1, 0x8a,
    0x9d, 0xf6, 0x3e, 0x00, 0x6c, 0x5d, 0x1c, 0x2d,
    0x34, 0x5b, 0x92, 0x5d, 0x8d, 0xc0, 0x0b, 0x41,
    0x04, 0x85, 0x2d, 0xb9, 0x9a, 0xc5, 0xc7, 0xcd,
    0xda, 0x85, 0x30, 0xa1, 0x13, 0xa0, 0xf4, 0xdb,
    0xb6, 0x11, 0x49, 0xf0, 0x5a, 0x73, 0x63, 0x26,
    0x8c, 0x71, 0xd9, 0x58, 0x08, 0xff, 0x2e, 0x65,
    0x26, 0x00,
};

static const uint8_t ed448_order[TF_ED448_PRIVATE_SEED_SIZE] = {
    0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
    0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
    0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
    0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
    0x00,
};

static int failures;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            failures++;                                                         \
        }                                                                       \
    } while (0)

static void test_shake256(void)
{
    static const uint8_t expected[64] = {
        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
        0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
        0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
        0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
        0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00,
        0xcb, 0x05, 0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6,
        0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86,
        0x40, 0x29, 0x2e, 0xac, 0xb3, 0xb7, 0xc4, 0xbe,
    };
    uint8_t actual[sizeof(expected)];

    CHECK(tf_shake256(NULL, 0, actual, sizeof(actual)) == TF_ED448_SUCCESS);
    CHECK(memcmp(actual, expected, sizeof(actual)) == 0);
    CHECK(tf_shake256(NULL, 1, actual, sizeof(actual)) == TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_shake256(NULL, 0, NULL, 1) == TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_shake256(NULL, 0, NULL, 0) == TF_ED448_SUCCESS);
}

static void test_rfc8032_vector_1(void)
{
    uint8_t derived[TF_ED448_PUBLIC_KEY_SIZE];
    uint8_t actual_signature[TF_ED448_SIGNATURE_SIZE];

    CHECK(tf_ed448_derive_public(private_seed, sizeof(private_seed),
                                 derived, sizeof(derived)) == TF_ED448_SUCCESS);
    CHECK(memcmp(derived, public_key, sizeof(derived)) == 0);
    CHECK(tf_ed448_sign(private_seed, sizeof(private_seed),
                        public_key, sizeof(public_key), NULL, 0,
                        actual_signature, sizeof(actual_signature)) ==
          TF_ED448_SUCCESS);
    CHECK(memcmp(actual_signature, signature, sizeof(actual_signature)) == 0);
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), NULL, 0,
                          signature, sizeof(signature)) == TF_ED448_SUCCESS);
}

static void test_deterministic_signing_and_tampering(void)
{
    static const uint8_t message[] = "ISO 15118-20 Ed448";
    uint8_t first[TF_ED448_SIGNATURE_SIZE];
    uint8_t second[TF_ED448_SIGNATURE_SIZE];
    uint8_t changed[TF_ED448_SIGNATURE_SIZE];
    uint8_t changed_public_key[TF_ED448_PUBLIC_KEY_SIZE];
    uint8_t changed_message[sizeof(message)];

    CHECK(tf_ed448_sign(private_seed, sizeof(private_seed),
                        public_key, sizeof(public_key), message, sizeof(message) - 1,
                        first, sizeof(first)) ==
          TF_ED448_SUCCESS);
    CHECK(tf_ed448_sign(private_seed, sizeof(private_seed),
                        public_key, sizeof(public_key), message, sizeof(message) - 1,
                        second, sizeof(second)) ==
          TF_ED448_SUCCESS);
    CHECK(memcmp(first, second, sizeof(first)) == 0);
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), message, sizeof(message) - 1,
                          first, sizeof(first)) ==
          TF_ED448_SUCCESS);

    memcpy(changed, first, sizeof(changed));
    changed[0] ^= 1;
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), message, sizeof(message) - 1,
                          changed, sizeof(changed)) !=
          TF_ED448_SUCCESS);

    memcpy(changed, first, sizeof(changed));
    changed[TF_ED448_PUBLIC_KEY_SIZE] ^= 1;
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), message, sizeof(message) - 1,
                          changed, sizeof(changed)) !=
          TF_ED448_SUCCESS);

    memcpy(changed_public_key, public_key, sizeof(changed_public_key));
    changed_public_key[0] ^= 1;
    CHECK(tf_ed448_verify(changed_public_key, sizeof(changed_public_key),
                          message, sizeof(message) - 1, first, sizeof(first)) !=
          TF_ED448_SUCCESS);

    memcpy(changed_message, message, sizeof(changed_message));
    changed_message[0] ^= 1;
    CHECK(tf_ed448_verify(public_key, sizeof(public_key),
                          changed_message, sizeof(message) - 1, first, sizeof(first)) !=
          TF_ED448_SUCCESS);
}

static void test_wrapper_validation(void)
{
    static const uint8_t message[] = "message";
    uint8_t output[TF_ED448_SIGNATURE_SIZE];
    uint8_t wrong_public_key[TF_ED448_PUBLIC_KEY_SIZE];
    uint8_t identity_r_signature[TF_ED448_SIGNATURE_SIZE];
    uint8_t noncanonical_s[TF_ED448_SIGNATURE_SIZE];
    uint8_t scalar_boundary[TF_ED448_SIGNATURE_SIZE];
    uint8_t noncanonical_point[TF_ED448_PUBLIC_KEY_SIZE];
    uint8_t small_order_keys[4][TF_ED448_PUBLIC_KEY_SIZE] = {
        {1},
        {0},
        {0},
        {0},
    };

    small_order_keys[1][0] = 0xfe;
    memset(small_order_keys[1] + 1, 0xff, 27);
    small_order_keys[1][28] = 0xfe;
    memset(small_order_keys[1] + 29, 0xff, 27);
    small_order_keys[2][TF_ED448_PUBLIC_KEY_SIZE - 1] = 0x80;

    memcpy(wrong_public_key, public_key, sizeof(wrong_public_key));
    wrong_public_key[0] ^= 1;
    CHECK(tf_ed448_sign(private_seed, sizeof(private_seed),
                        wrong_public_key, sizeof(wrong_public_key),
                        message, sizeof(message) - 1, output, sizeof(output)) ==
          TF_ED448_PUBLIC_KEY_MISMATCH);

    for (size_t i = 0; i < 4; ++i) {
        memcpy(identity_r_signature, signature, sizeof(identity_r_signature));
        memcpy(identity_r_signature, small_order_keys[i], TF_ED448_PUBLIC_KEY_SIZE);
        CHECK(tf_ed448_verify(small_order_keys[i], sizeof(small_order_keys[i]),
                              NULL, 0, signature, sizeof(signature)) ==
              TF_ED448_INVALID_PUBLIC_KEY);
        CHECK(tf_ed448_verify(public_key, sizeof(public_key), NULL, 0,
                              identity_r_signature, sizeof(identity_r_signature)) ==
              TF_ED448_INVALID_SIGNATURE);
        CHECK(tf_ed448_validate_public(small_order_keys[i], sizeof(small_order_keys[i])) ==
              TF_ED448_INVALID_PUBLIC_KEY);
    }

    memcpy(noncanonical_s, signature, sizeof(noncanonical_s));
    memset(noncanonical_s + TF_ED448_PUBLIC_KEY_SIZE, 0xff,
           TF_ED448_PRIVATE_SEED_SIZE);
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), NULL, 0,
                          noncanonical_s, sizeof(noncanonical_s)) ==
          TF_ED448_INVALID_SIGNATURE);

    memcpy(noncanonical_point, public_key, sizeof(noncanonical_point));
    noncanonical_point[TF_ED448_PUBLIC_KEY_SIZE - 1] |= 1;
    CHECK(tf_ed448_verify(noncanonical_point, sizeof(noncanonical_point), NULL, 0,
                          signature, sizeof(signature)) == TF_ED448_INVALID_PUBLIC_KEY);
    memcpy(identity_r_signature, signature, sizeof(identity_r_signature));
    memcpy(identity_r_signature, noncanonical_point, sizeof(noncanonical_point));
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), NULL, 0,
                          identity_r_signature, sizeof(identity_r_signature)) ==
          TF_ED448_INVALID_SIGNATURE);

    memcpy(scalar_boundary, signature, sizeof(scalar_boundary));
    memcpy(scalar_boundary + TF_ED448_PUBLIC_KEY_SIZE,
           ed448_order, sizeof(ed448_order));
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), NULL, 0,
                          scalar_boundary, sizeof(scalar_boundary)) ==
          TF_ED448_INVALID_SIGNATURE);
    scalar_boundary[TF_ED448_PUBLIC_KEY_SIZE]++;
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), NULL, 0,
                          scalar_boundary, sizeof(scalar_boundary)) ==
          TF_ED448_INVALID_SIGNATURE);

    memcpy(scalar_boundary, signature, sizeof(scalar_boundary));
    for (size_t i = 0, carry = 1; i < sizeof(ed448_order); ++i) {
        size_t index = TF_ED448_PUBLIC_KEY_SIZE + i;
        unsigned sum = scalar_boundary[index] + ed448_order[i] + carry;
        scalar_boundary[index] = (uint8_t)sum;
        carry = sum >> 8;
    }
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), NULL, 0,
                          scalar_boundary, sizeof(scalar_boundary)) ==
          TF_ED448_INVALID_SIGNATURE);

    CHECK(tf_ed448_derive_public(NULL, sizeof(private_seed),
                                 wrong_public_key, sizeof(wrong_public_key)) ==
          TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_derive_public(private_seed, sizeof(private_seed) - 1,
                                 wrong_public_key, sizeof(wrong_public_key)) ==
          TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_derive_public(private_seed, sizeof(private_seed), NULL,
                                 sizeof(wrong_public_key)) == TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_derive_public(private_seed, sizeof(private_seed), wrong_public_key,
                                 sizeof(wrong_public_key) - 1) == TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_validate_public(public_key, sizeof(public_key)) == TF_ED448_SUCCESS);
    CHECK(tf_ed448_validate_public(NULL, sizeof(public_key)) == TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_validate_public(public_key, sizeof(public_key) - 1) ==
          TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_sign(NULL, sizeof(private_seed), public_key, sizeof(public_key),
                        message, sizeof(message) - 1, output, sizeof(output)) ==
          TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_sign(private_seed, sizeof(private_seed), NULL, sizeof(public_key),
                        message, sizeof(message) - 1, output, sizeof(output)) ==
          TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_sign(private_seed, sizeof(private_seed), public_key, sizeof(public_key),
                        message, sizeof(message) - 1, NULL, sizeof(output)) ==
          TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_sign(private_seed, sizeof(private_seed), public_key, sizeof(public_key),
                        NULL, 1, output, sizeof(output)) ==
          TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_sign(private_seed, sizeof(private_seed) - 1,
                        public_key, sizeof(public_key), message, sizeof(message) - 1,
                        output, sizeof(output)) == TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_sign(private_seed, sizeof(private_seed),
                        public_key, sizeof(public_key) - 1, message, sizeof(message) - 1,
                        output, sizeof(output)) == TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_sign(private_seed, sizeof(private_seed), public_key, sizeof(public_key),
                        message, sizeof(message) - 1, output, sizeof(output) - 1) ==
          TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_verify(NULL, sizeof(public_key), NULL, 0,
                          signature, sizeof(signature)) == TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), NULL, 0,
                          NULL, sizeof(signature)) == TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), NULL, 1,
                          signature, sizeof(signature)) ==
          TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_verify(public_key, sizeof(public_key) - 1, NULL, 0,
                          signature, sizeof(signature)) == TF_ED448_INVALID_ARGUMENT);
    CHECK(tf_ed448_verify(public_key, sizeof(public_key), NULL, 0,
                          signature, sizeof(signature) - 1) ==
          TF_ED448_INVALID_ARGUMENT);
}

int main(void)
{
    test_shake256();
    test_rfc8032_vector_1();
    test_deterministic_signing_and_tampering();
    test_wrapper_validation();

    if (failures != 0) {
        fprintf(stderr, "%d test checks failed\n", failures);
        return 1;
    }

    puts("tf_ed448: all tests passed");
    return 0;
}
