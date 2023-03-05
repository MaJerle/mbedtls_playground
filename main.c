#include <stdio.h>
#include <string.h>
#include "windows.h"

#include "mbedtls_config.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"

/* Raw input data*/
const uint8_t data_raw_input[] = {
#include "keys/data_raw_input_array.txt"
};

/* SHA256 of raw input data */
const uint8_t data_raw_hash_digest[] = {
#include "keys/data_raw_hash_digest_array.txt"
};

/* Signature of hash of raw data with private key */
const uint8_t signature_der[] = {
#include "keys/signature_der_array.txt"
};
const uint8_t signature_p1363[] = {
#include "keys/signature_p1363_array.txt"
};

/* ECC public key - compressed binary */
const uint8_t ecc_public_key_compressed_bin[] = {
#include "keys/ecc_public_key_compressed_array.txt"
};

/* ECC public key - uncompressed binary */
const uint8_t ecc_public_key_uncompressed_bin[] = {
#include "keys/ecc_public_key_uncompressed_array.txt"
};

/* ECC public key full text */
const uint8_t ecc_public_key_text[] = {
#include "keys/public.ec.oneline.key"
};

/* ECC private key full text */
const uint8_t ecc_private_key_text[] = {
#include "keys/private.ec.oneline.key"
};

/* AES encryption/decryption part*/
const uint8_t aes_iv[] = {
#include "keys/aes_iv_array.txt"
};
const uint8_t aes128_key[] = {
#include "keys/aes128_key_array.txt"
};
const uint8_t aes192_key[] = {
#include "keys/aes192_key_array.txt"
};
const uint8_t aes256_key[] = {
#include "keys/aes256_key_array.txt"
};

/* Encrypted information */
const uint8_t data_encrypted_aes128[] = {
#include "keys/data_encrypted_aes128_array.txt"
};
const uint8_t data_encrypted_aes192[] = {
#include "keys/data_encrypted_aes192_array.txt"
};
const uint8_t data_encrypted_aes256[] = {
#include "keys/data_encrypted_aes256_array.txt"
};

/* Hash of encrypted data*/
const uint8_t data_encrypted_aes128_hash_digest[] = {
#include "keys/data_encrypted_aes128_hash_digest_array.txt"
};
const uint8_t data_encrypted_aes192_hash_digest[] = {
#include "keys/data_encrypted_aes192_hash_digest_array.txt"
};
const uint8_t data_encrypted_aes256_hash_digest[] = {
#include "keys/data_encrypted_aes256_hash_digest_array.txt"
};

int
main(void) {
    volatile int res;
    mbedtls_ecdsa_context ecdsa_ctx;
    mbedtls_pk_context pubkey_ctx;

    /* Test HASH - calculate hash of raw data and compare with calculated one from python script */
    {
        uint8_t hash_calculated[32];

        printf("HASH SHA256 calculation\r\n");
        res = mbedtls_sha256(data_raw_input, sizeof(data_raw_input), hash_calculated, 0);
        printf("mbedtls_sha256: %d\r\n", res);
        if (memcmp(hash_calculated, data_raw_hash_digest, sizeof(hash_calculated)) == 0) {
            printf("Hash is equal\r\n");
        } else {
            printf("Hash does not match\r\n");
        }
        printf("-----\r\n");
    }

    /*
     * Public key cryphography playground shows different way of parsing
     * actual public key (DER format (string) or binary format) and 
     * different types of signature representation (DER or P1363).
     */

    /*
     * Read this SO post for details:
     *
     * https://stackoverflow.com/questions/75635019/mbedtls-ecdsa-verification-fails/75641568#
     */

    /* 
     * Public key format:   DER/PEM (String based public key, --- BEGIN PUBLIC KEY --- type of message)
     * Signature format :   DER     (70, 71 or 72 bytes long)
     */
    {
        /* Parse public key */
        mbedtls_pk_init(&pubkey_ctx);
        res = mbedtls_pk_parse_public_key(&pubkey_ctx, ecc_public_key_text, sizeof(ecc_public_key_text));
        printf("mbedtls_pk_parse_public_key: %d\r\n", res);

        /* Verify with DER native format support */
        res = mbedtls_pk_verify(&pubkey_ctx, MBEDTLS_MD_SHA256, data_raw_hash_digest, sizeof(data_raw_hash_digest),
                                signature_der, sizeof(signature_der));
        printf("mbedtls_pk_verify: %d\r\n", res);
        printf("-----\r\n");

        /* Free objects */
        mbedtls_pk_free(&pubkey_ctx);
    }

    /* 
     * Public key format:   binary  (65-bytes long, 0x04 as first byte)
     * Signature format :   DER     (70, 71 or 72 bytes long)
     */
    {
        printf("Public key - ECDSA verification with binary format\r\n");

        /* Parse public key */
        mbedtls_ecdsa_init(&ecdsa_ctx);
        mbedtls_ecp_group_load(&ecdsa_ctx.private_grp, MBEDTLS_ECP_DP_SECP256R1);
        res = mbedtls_ecp_point_read_binary(&ecdsa_ctx.private_grp, &ecdsa_ctx.private_Q,
                                            ecc_public_key_uncompressed_bin, sizeof(ecc_public_key_uncompressed_bin));
        printf("mbedtls_ecp_point_read_binary: %d\r\n", res);

        /* Verify with DER native format support */
        res = mbedtls_ecdsa_read_signature(&ecdsa_ctx, data_raw_hash_digest, sizeof(data_raw_hash_digest),
                                           signature_der, sizeof(signature_der));
        printf("mbedtls_ecdsa_read_signature: %d\r\n", res);
        printf("-----\r\n");
    }

    /* 
     * Public key format:   binary  (65-bytes long, 0x04 as first byte)
     * Signature format :   P1363   (64-bytes long, r|s)
     */
    {
#define SIGNATURE_LEN (sizeof(signature_p1363))

        /* Parse public key in binary format */
        printf("Parse public key in binary format\r\n");
        mbedtls_ecdsa_init(&ecdsa_ctx);
        mbedtls_ecp_group_load(&ecdsa_ctx.private_grp, MBEDTLS_ECP_DP_SECP256R1);
        res = mbedtls_ecp_point_read_binary(&ecdsa_ctx.private_grp, &ecdsa_ctx.private_Q,
                                            ecc_public_key_uncompressed_bin, sizeof(ecc_public_key_uncompressed_bin));
        printf("mbedtls_ecp_point_read_binary: %d\r\n", res);
        printf("-----\r\n");

        /* Manually structure R and S components */
        printf("Parse signature in P1363 format to r and s big numbers\r\n");
        mbedtls_mpi r, s;
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        mbedtls_mpi_read_binary(&r, signature_p1363, SIGNATURE_LEN / 2);
        mbedtls_mpi_read_binary(&s, signature_p1363 + SIGNATURE_LEN / 2, SIGNATURE_LEN / 2);

        /* Run verify with ecdsa */
        res = mbedtls_ecdsa_verify(&ecdsa_ctx.private_grp, data_raw_hash_digest, sizeof(data_raw_hash_digest),
                                   &ecdsa_ctx.private_Q, &r, &s);
        printf("mbedtls_ecdsa_verify: %d\r\n", res);
        printf("-----\r\n");

        /* Free objects */
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_ecdsa_free(&ecdsa_ctx);
#undef SIGNATURE_LEN
    }

    /* 
     * Public key format:   DER/PEM (String based public key, --- BEGIN PUBLIC KEY --- type of message)
     * Signature format :   P1363   (64-bytes long, r|s)
     */
    {
#define SIGNATURE_LEN (sizeof(signature_p1363))
        /* Parse public key */
        mbedtls_pk_init(&pubkey_ctx);
        res = mbedtls_pk_parse_public_key(&pubkey_ctx, ecc_public_key_text, sizeof(ecc_public_key_text));
        printf("mbedtls_pk_parse_public_key: %d\r\n", res);
        /* TODO: get pair */

        /* Parse P1363 signature */
        mbedtls_mpi r, s;
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        mbedtls_mpi_read_binary(&r, signature_p1363, SIGNATURE_LEN / 2);
        mbedtls_mpi_read_binary(&s, signature_p1363 + SIGNATURE_LEN / 2, SIGNATURE_LEN / 2);

        /* Get ECDSA verify context from pk structure */
        mbedtls_ecdsa_context* ctx = pubkey_ctx.private_pk_ctx;
        res = mbedtls_ecdsa_verify(&ctx->private_grp, data_raw_hash_digest, sizeof(data_raw_hash_digest),
                                   &ctx->private_Q, &r, &s);
        printf("mbedtls_ecdsa_verify: %d\r\n", res);
        printf("-----\r\n");

        /* Free objects */
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_pk_free(&pubkey_ctx);
#undef SIGNATURE_LEN
    }
    return 0;

    /* Test AES mbedTLS -> CBC mode */
    {
        mbedtls_aes_context aes_ctx;
        uint8_t aes_iv_tmp[sizeof(aes_iv)];
        uint8_t data_encrypted_output[(sizeof(data_raw_input) + 15) & ~15];
        uint8_t hash_calculated[32];

        struct {
            uint16_t aes_bits;
            const uint8_t* aes_key;
            const uint8_t* ref_enc_data;
            const uint8_t* ref_enc_data_hash;
        } test_table[] = {
            {
                .aes_bits = 128,
                .aes_key = aes128_key,
                .ref_enc_data = data_encrypted_aes128,
                .ref_enc_data_hash = data_encrypted_aes128_hash_digest,
            },
            {
                .aes_bits = 192,
                .aes_key = aes192_key,
                .ref_enc_data = data_encrypted_aes192,
                .ref_enc_data_hash = data_encrypted_aes192_hash_digest,
            },
            {
                .aes_bits = 256,
                .aes_key = aes256_key,
                .ref_enc_data = data_encrypted_aes256,
                .ref_enc_data_hash = data_encrypted_aes256_hash_digest,
            },
        };

        printf("AES encrypt\r\n");

        /* Run test for all AES variants */
        for (size_t i = 0; i < sizeof(test_table) / sizeof(test_table[0]); ++i) {
            printf("AES-%u test\r\n", (unsigned)test_table[i].aes_bits);
            mbedtls_aes_init(&aes_ctx);
            memcpy(aes_iv_tmp, aes_iv, sizeof(aes_iv));

            /* Encrypt text */
            mbedtls_aes_setkey_enc(&aes_ctx, test_table[i].aes_key, test_table[i].aes_bits);
            res = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, sizeof(data_raw_input), aes_iv_tmp,
                                        data_raw_input, data_encrypted_output);
            printf("mbedtls_aes_crypt_cbc: %d\r\n", res);

            /* Compare for a match */
            if (memcmp(data_encrypted_output, test_table[i].ref_enc_data, sizeof(data_encrypted_output)) == 0) {
                printf("AES encryption matches reference data\r\n");
            } else {
                printf("AES encryption failed\r\n");
            }

            /* Make a hash of the encrypted text and compare with refrence */
            res = mbedtls_sha256(data_encrypted_output, sizeof(data_encrypted_output), hash_calculated, 0);
            printf("mbedtls_sha256: %d\r\n", res);

            /* Compare for a match */
            if (memcmp(hash_calculated, test_table[i].ref_enc_data_hash, sizeof(hash_calculated)) == 0) {
                printf("Hash of encrypted data matches reference hash\r\n");
            } else {
                printf("Hash of encrypted data does not match reference input\r\n");
            }
            printf("--\r\n");
        }
        printf("-----\r\n");
    }
    return 0;
}
