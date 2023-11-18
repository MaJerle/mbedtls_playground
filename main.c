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

extern int cert_playground(void);

int
main(void) {
    volatile int res;

    cert_playground();
    return 0;

    /* Convert unique ID to very random one way function string + use SHA2 as a result */
    {
        uint8_t hash_calc[32], val;
        mbedtls_sha256_context sha_ctx;

        /* List of some devices with its random UID numbers */
        uint8_t device_ids[][12] = {
            {0x43, 0x02, 0x33, 0x07, 0x36, 0x31, 0x47, 0x32, 0x06, 0xE3, 0x00, 0x30},
            {0x43, 0x02, 0x25, 0x07, 0x36, 0x31, 0x47, 0x32, 0x06, 0xCF, 0x00, 0x30},
            {0x43, 0x02, 0x24, 0x07, 0x36, 0x31, 0x47, 0x32, 0x06, 0xD1, 0x00, 0x30},
        };

        for (size_t i = 0; i < sizeof(device_ids) / sizeof(device_ids[0]); ++i) {
            const uint8_t* id = &device_ids[i];
            mbedtls_sha256_init(&sha_ctx);

            /* Process all bytes */
            for (size_t j = 0; j < sizeof(device_ids[0]) / sizeof(device_ids[0][0]); ++j) {
                val = id[j];
                mbedtls_sha256_update(&sha_ctx, &val, 1);
                val = id[11 - j];
                mbedtls_sha256_update(&sha_ctx, &val, 1);
                val = id[j] ^ id[11 - j];
                mbedtls_sha256_update(&sha_ctx, &val, 1);
            }
            mbedtls_sha256_finish(&sha_ctx, hash_calc);

            printf("Index: %u; RAW device ID: ", (unsigned)i);
            for (size_t index = 0; index < sizeof(device_ids[0]) / sizeof(device_ids[0][0]); ++index) {
                printf("%02X", (unsigned)id[index]);
            }
            printf("; HASH: ");
            for (size_t index = 0; index < sizeof(hash_calc) / sizeof(hash_calc[0]); ++index) {
                printf("%02X", (unsigned)hash_calc[index]);
            }
            printf("\r\n");
        }
        return 0;
    }

    /* Test HASH - calculate hash of raw data and compare with calculated one from python script */
    {
        uint8_t hash_calc[32];

        printf("HASH SHA256 calculation\r\n");
        res = mbedtls_sha256(data_raw_input, sizeof(data_raw_input), hash_calc, 0);
        printf("mbedtls_sha256: %d\r\n", res);
        if (memcmp(hash_calc, data_raw_hash_digest, sizeof(hash_calc)) == 0) {
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
     * PublicKey format:   DER/PEM (String based public key, --- BEGIN PUBLIC KEY --- type of message)
     * Signature format:   DER     (70, 71 or 72 bytes long)
     */
    {
        mbedtls_pk_context pubkey_ctx;

        printf("Public key - ECDSA verification:\r\nPublicKey format: DER/PEM\r\nSignature format: DER\r\n\r\n");

        /* Parse public key */
        mbedtls_pk_init(&pubkey_ctx);
        res = mbedtls_pk_parse_public_key(&pubkey_ctx, ecc_public_key_text, sizeof(ecc_public_key_text));
        printf("mbedtls_pk_parse_public_key: %d\r\n", res);

        /* Verify with DER native format support */
        res = mbedtls_pk_verify(&pubkey_ctx, MBEDTLS_MD_SHA256, data_raw_hash_digest, sizeof(data_raw_hash_digest),
                                signature_der, sizeof(signature_der));
        printf("mbedtls_pk_verify: %d\r\n", res);

        /* Free objects */
        mbedtls_pk_free(&pubkey_ctx);

        /* Done */
        printf("-----\r\n");
    }

    /* 
     * PublicKey format:   binary  (65-bytes long, 0x04 as first byte)
     * Signature format:   DER     (70, 71 or 72 bytes long)
     */
    {
        mbedtls_ecdsa_context ecdsa_ctx;
        mbedtls_ecp_group group;
        mbedtls_ecp_point p;

        printf("Public key - ECDSA verification:\r\nPublicKey format: Binary\r\nSignature format: DER\r\n\r\n");

        /* Parse public key */
        mbedtls_ecdsa_init(&ecdsa_ctx);
        mbedtls_ecp_group_init(&group);
        mbedtls_ecp_point_init(&p);
        mbedtls_ecp_group_load(&ecdsa_ctx.private_grp, MBEDTLS_ECP_DP_SECP256R1);

        /* Parse and verify using private variables */
        res = mbedtls_ecp_point_read_binary(&ecdsa_ctx.private_grp, &ecdsa_ctx.private_Q,
                                            ecc_public_key_uncompressed_bin, sizeof(ecc_public_key_uncompressed_bin));
        printf("mbedtls_ecp_point_read_binary: %d\r\n", res);
        res = mbedtls_ecdsa_read_signature(&ecdsa_ctx, data_raw_hash_digest, sizeof(data_raw_hash_digest),
                                           signature_der, sizeof(signature_der));
        printf("mbedtls_ecdsa_read_signature: %d\r\n", res);

        /* Parse using new variables */
        res = mbedtls_ecp_point_read_binary(&group, &p, ecc_public_key_uncompressed_bin,
                                            sizeof(ecc_public_key_uncompressed_bin));
        printf("mbedtls_ecp_point_read_binary: %d\r\n", res);
        /* TODO: How to verify?? */

        /* Free objects */
        mbedtls_ecdsa_free(&ecdsa_ctx);
        mbedtls_ecp_group_free(&group);
        mbedtls_ecp_point_free(&p);

        /* Done */
        printf("-----\r\n");
    }

    /* 
     * PublicKey format:   binary  (65-bytes long, 0x04 as first byte)
     * Signature format:   P1363   (64-bytes long, r|s)
     */
    {
#define SIGNATURE_LEN (sizeof(signature_p1363))
        mbedtls_mpi r, s;
        mbedtls_ecp_group group;
        mbedtls_ecp_point q;

        printf("Public key - ECDSA verification:\r\nPublicKey format: Binary\r\nSignature format: P1363\r\n\r\n");

        /* Initialize all modules */
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        mbedtls_ecp_point_init(&q);
        mbedtls_ecp_group_init(&group);

        /* Parse public key in binary format */
        mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
        res = mbedtls_ecp_point_read_binary(&group, &q, ecc_public_key_uncompressed_bin,
                                            sizeof(ecc_public_key_uncompressed_bin));
        printf("mbedtls_ecp_point_read_binary: %d\r\n", res);

        /* Parse signature in P1363 format to r and s big numbers */
        res = mbedtls_mpi_read_binary(&r, signature_p1363, SIGNATURE_LEN / 2);
        printf("mbedtls_mpi_read_binary: %d\r\n", res);
        res = mbedtls_mpi_read_binary(&s, signature_p1363 + SIGNATURE_LEN / 2, SIGNATURE_LEN / 2);
        printf("mbedtls_mpi_read_binary: %d\r\n", res);

        /* Run verify with ecdsa */
        res = mbedtls_ecdsa_verify(&group, data_raw_hash_digest, sizeof(data_raw_hash_digest), &q, &r, &s);
        printf("mbedtls_ecdsa_verify: %d\r\n", res);

        /* Free objects */
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_ecp_point_free(&q);
        mbedtls_ecp_group_free(&group);

        /* Done */
        printf("-----\r\n");
#undef SIGNATURE_LEN
    }

    /* 
     * PublicKey format:   DER/PEM (String based public key, --- BEGIN PUBLIC KEY --- type of message)
     * Signature format:   P1363   (64-bytes long, r|s)
     * 
     * Steps to follow:
     * 
     * - Parse public key with PK module
     * - Extract EC parameters -> generate key pair
     * - Extract group, D and Q values from the pair
     * - Parse P1363 format into 2 big numbers R and S
     * - Call ecdsa verification function
     */
    {
#define SIGNATURE_LEN (sizeof(signature_p1363))
        mbedtls_pk_context pubkey_ctx;
        mbedtls_ecp_keypair* pair;
        mbedtls_ecp_group group;
        mbedtls_mpi d;
        mbedtls_ecp_point q;
        mbedtls_mpi r, s;

        printf("Public key - ECDSA verification:\r\nPublicKey format: DER/PEM\r\nSignature format: P1363\r\n\r\n");

        /* Initialize all values to its default state - avoid any segmentation faults */
        mbedtls_pk_init(&pubkey_ctx);
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        mbedtls_ecp_group_init(&group);
        mbedtls_mpi_init(&d);
        mbedtls_ecp_point_init(&q);

        /* Parse public key */
        res = mbedtls_pk_parse_public_key(&pubkey_ctx, ecc_public_key_text, sizeof(ecc_public_key_text));
        printf("mbedtls_pk_parse_public_key: %d\r\n", res);

        /* Get EC pair from parsed public key */
        pair = mbedtls_pk_ec(pubkey_ctx);
        printf("mbedtls_pk_ec: %p\r\n", (void*)pair);

        /* Export data from the pair - required for ECDSA verification purpose */
        res = mbedtls_ecp_export(pair, &group, &d, &q);
        printf("mbedtls_ecp_export: %d\r\n", res);

        /* Parse P1363 signature to 2 big nums */
        mbedtls_mpi_read_binary(&r, signature_p1363, SIGNATURE_LEN / 2);
        mbedtls_mpi_read_binary(&s, signature_p1363 + SIGNATURE_LEN / 2, SIGNATURE_LEN / 2);

        /* Get ECDSA verify context from parsed pk structure */
        res = mbedtls_ecdsa_verify(&group, data_raw_hash_digest, sizeof(data_raw_hash_digest), &q, &r, &s);
        printf("mbedtls_ecdsa_verify: %d\r\n", res);

        /* Free objects */
        mbedtls_pk_free(&pubkey_ctx);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_ecp_group_free(&group);
        mbedtls_mpi_free(&d);
        mbedtls_ecp_point_free(&q);

        /* Done */
        printf("-----\r\n");
#undef SIGNATURE_LEN
    }
    return 0;

    /* Test AES mbedTLS -> CBC mode */
    {
        mbedtls_aes_context aes_ctx;
        uint8_t aes_iv_tmp[sizeof(aes_iv)];
        uint8_t data_encrypted_output[(sizeof(data_raw_input) + 15) & ~15];
        uint8_t hash_calc[32];

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
            res = mbedtls_sha256(data_encrypted_output, sizeof(data_encrypted_output), hash_calc, 0);
            printf("mbedtls_sha256: %d\r\n", res);

            /* Compare for a match */
            if (memcmp(hash_calc, test_table[i].ref_enc_data_hash, sizeof(hash_calc)) == 0) {
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
