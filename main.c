#include <stdio.h>
#include <string.h>
#include "windows.h"

#include "mbedtls_config.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"

/* Raw input data*/
static const uint8_t data_raw_input[] = {
#include "keys/data_raw_input_array.txt"
};

/* SHA256 of raw input data */
static const uint8_t data_raw_hash_digest[] = {
#include "keys/data_raw_hash_digest_array.txt"
};

/* Signature of hash of raw data with private key */
static const uint8_t signature_der[] = {
#include "keys/signature_der_array.txt"
};
static const uint8_t signature_p1363[] = {
#include "keys/signature_p1363_array.txt"
};

/* ECC public key - compressed binary */
static const uint8_t ecc_public_key_compressed_bin[] = {
#include "keys/ecc_public_key_compressed_array.txt"
};

/* ECC public key - uncompressed binary */
static const uint8_t ecc_public_key_uncompressed_bin[] = {
#include "keys/ecc_public_key_uncompressed_array.txt"
};

/* ECC public key full text */
static const uint8_t ecc_public_key_text[] = {
#include "keys/public.ec.oneline.key"
};

/* ECC private key full text */
static const uint8_t ecc_private_key_text[] = {
#include "keys/private.ec.oneline.key"
};

/* AES encryption/decryption part*/
static const uint8_t aes_iv[] = {
#include "keys/aes_iv_array.txt"
};
static const uint8_t aes128_key[] = {
#include "keys/aes128_key_array.txt"
};
static const uint8_t aes192_key[] = {
#include "keys/aes192_key_array.txt"
};
static const uint8_t aes256_key[] = {
#include "keys/aes256_key_array.txt"
};

/* Encrypted information */
static const uint8_t data_encrypted_aes128[] = {
#include "keys/data_encrypted_aes128_array.txt"
};
static const uint8_t data_encrypted_aes192[] = {
#include "keys/data_encrypted_aes192_array.txt"
};
static const uint8_t data_encrypted_aes256[] = {
#include "keys/data_encrypted_aes256_array.txt"
};

/* Hash of encrypted data*/
static const uint8_t data_encrypted_aes128_hash_digest[] = {
#include "keys/data_encrypted_aes128_hash_digest_array.txt"
};
static const uint8_t data_encrypted_aes192_hash_digest[] = {
#include "keys/data_encrypted_aes192_hash_digest_array.txt"
};
static const uint8_t data_encrypted_aes256_hash_digest[] = {
#include "keys/data_encrypted_aes256_hash_digest_array.txt"
};

extern int cert_playground(void);
extern int ecdh_playground(void);
extern int ecdsa_playground(void);

int
main(void) {
    volatile int res;

    ecdsa_playground();
    return 0;

#if 0
    ecdh_playground();
    return 0;

    cert_playground();
    return 0;
#endif

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
            const uint8_t* id = device_ids[i];
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
