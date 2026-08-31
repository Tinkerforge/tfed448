#include "tf_ed448.h"

#include <openssl/evp.h>

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

static int openssl_sign(
    EVP_PKEY *key,
    const uint8_t *message,
    size_t message_len,
    uint8_t signature[TF_ED448_SIGNATURE_SIZE])
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    size_t signature_len = TF_ED448_SIGNATURE_SIZE;
    int success = context != NULL &&
                  EVP_DigestSignInit(context, NULL, NULL, NULL, key) == 1 &&
                  EVP_DigestSign(context, signature, &signature_len, message, message_len) == 1 &&
                  signature_len == TF_ED448_SIGNATURE_SIZE;

    EVP_MD_CTX_free(context);
    return success;
}

static int openssl_verify(
    EVP_PKEY *key,
    const uint8_t *message,
    size_t message_len,
    const uint8_t signature[TF_ED448_SIGNATURE_SIZE])
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int success = context != NULL &&
                  EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 &&
                  EVP_DigestVerify(context, signature, TF_ED448_SIGNATURE_SIZE,
                                   message, message_len) == 1;

    EVP_MD_CTX_free(context);
    return success;
}

int main(void)
{
    static const size_t message_lengths[] = {0, 1, 13, 64, 256, 1023};
    uint8_t message[1023];
    uint8_t public_key[TF_ED448_PUBLIC_KEY_SIZE];
    uint8_t openssl_public_key[TF_ED448_PUBLIC_KEY_SIZE];
    uint8_t tf_signature[TF_ED448_SIGNATURE_SIZE];
    uint8_t openssl_signature[TF_ED448_SIGNATURE_SIZE];
    size_t openssl_public_key_len = sizeof(openssl_public_key);
    EVP_PKEY *private_key;
    EVP_PKEY *public_only_key;

    for (size_t i = 0; i < sizeof(message); ++i) {
        message[i] = (uint8_t)(i * 37 + 11);
    }

    private_key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED448, NULL, private_seed, sizeof(private_seed));
    if (private_key == NULL ||
        EVP_PKEY_get_raw_public_key(
            private_key, openssl_public_key, &openssl_public_key_len) != 1 ||
        openssl_public_key_len != sizeof(openssl_public_key) ||
        tf_ed448_derive_public(private_seed, sizeof(private_seed),
                               public_key, sizeof(public_key)) != TF_ED448_SUCCESS ||
        memcmp(public_key, openssl_public_key, sizeof(public_key)) != 0) {
        fputs("Ed448 public-key derivation interoperability failed\n", stderr);
        EVP_PKEY_free(private_key);
        return 1;
    }

    public_only_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED448, NULL, public_key, sizeof(public_key));
    if (public_only_key == NULL) {
        fputs("OpenSSL rejected the derived Ed448 public key\n", stderr);
        EVP_PKEY_free(private_key);
        return 1;
    }

    for (size_t i = 0; i < sizeof(message_lengths) / sizeof(message_lengths[0]); ++i) {
        size_t message_len = message_lengths[i];
        const uint8_t *message_ptr = message_len == 0 ? (const uint8_t *)"" : message;

        if (tf_ed448_sign(private_seed, sizeof(private_seed),
                          public_key, sizeof(public_key), message_ptr, message_len,
                          tf_signature, sizeof(tf_signature)) != TF_ED448_SUCCESS ||
            !openssl_sign(private_key, message_ptr, message_len, openssl_signature) ||
            memcmp(tf_signature, openssl_signature, sizeof(tf_signature)) != 0 ||
            tf_ed448_verify(public_key, sizeof(public_key), message_ptr, message_len,
                            openssl_signature, sizeof(openssl_signature)) != TF_ED448_SUCCESS ||
            !openssl_verify(public_only_key, message_ptr, message_len, tf_signature)) {
            fprintf(stderr, "Ed448 interoperability failed at message length %zu\n",
                    message_len);
            EVP_PKEY_free(public_only_key);
            EVP_PKEY_free(private_key);
            return 1;
        }
    }

    EVP_PKEY_free(public_only_key);
    EVP_PKEY_free(private_key);
    puts("tf_ed448: OpenSSL interoperability passed");
    return 0;
}
