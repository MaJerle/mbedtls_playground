#include <stdio.h>
#include <string.h>
#include "windows.h"

#include "mbedtls_config.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
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

int
ecdsa_playground(void) {
    volatile int res;

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

        printf("Public key - ECDSA verification:\r\n");
        printf("PublicKey format: DER/PEM\r\n");
        printf("Signature format: DER\r\n\r\n");

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
     * PublicKey format:   binary  (65-bytes long, typically 0x04 as first byte + X + Y components)
     * Signature format:   DER     (70, 71 or 72 bytes long)
     */
    {
        mbedtls_ecdsa_context ecdsa_ctx;
        mbedtls_ecp_group pki_group;
        mbedtls_ecp_point pki_pub_key_point;
        mbedtls_mpi sign_r;
        mbedtls_mpi sign_s;

        printf("Public key - ECDSA verification:\r\nPublicKey format: Binary\r\nSignature format: DER\r\n\r\n");

        /* Parse public key */
        mbedtls_ecdsa_init(&ecdsa_ctx);
        mbedtls_ecp_group_init(&pki_group);
        mbedtls_ecp_point_init(&pki_pub_key_point);
        mbedtls_mpi_init(&sign_r);
        mbedtls_mpi_init(&sign_s);

        /* Set the public key type, SECP256R1 */
        mbedtls_ecp_group_load(&pki_group, MBEDTLS_ECP_DP_SECP256R1);

        /* Parse the public key, that is in binary format */
        res = mbedtls_ecp_point_read_binary(&pki_group, &pki_pub_key_point, ecc_public_key_uncompressed_bin,
                                            sizeof(ecc_public_key_uncompressed_bin));
        printf("mbedtls_ecp_point_read_binary: %d\r\n", res);

        /* We need to parse DER signature to R and S variables, then call */
        //mbedtls_ecdsa_verify()...

        /* Free objects */
        mbedtls_ecdsa_free(&ecdsa_ctx);
        mbedtls_ecp_group_free(&pki_group);
        mbedtls_ecp_point_free(&pki_pub_key_point);
        mbedtls_mpi_init(&sign_r);
        mbedtls_mpi_init(&sign_s);

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

        /* Export data from the pair - required for ECDSA verification purpose */
        res = mbedtls_ecp_export(mbedtls_pk_ec(pubkey_ctx), &group, &d, &q);
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

    return 1;
}
