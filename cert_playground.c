#include <stdio.h>
#include <string.h>
#include "windows.h"

#include "mbedtls_config.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

/*
 * This demo code demonstrates how we could implement a challenge-response 
 * implementation to detect if device is genuine, using ECDSA signature and device certificate
 * 
 * Root certificate   -> self signed
 * Device certificate -> signed by device
 */

static uint8_t ec_root_ca_str[] = {
#include "certificates/ec_root.crt.hexarr"
    ,
    0,
};
static uint8_t ec_root_key_str[] = {
#include "certificates/ec_root.key.hexarr"
    ,
    0,
};
static uint8_t ec_device_ca_str[] = {
#include "certificates/ec_device.crt.hexarr"
    ,
    0,
};
static uint8_t ec_device_key_str[] = {
#include "certificates/ec_device.key.hexarr"
    ,
    0,
};

static mbedtls_x509_crt crt_root;
static mbedtls_pk_context key_root;
static mbedtls_x509_crt crt_device;
static mbedtls_pk_context key_device;

static uint8_t hash[32];
static uint8_t signature[128];
static size_t signature_len;

int
fn_rng(void* par, unsigned char* output, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        output[i] = len * 2 + i - 1;
    }
    return 0;
}

int
cert_playground(void) {
    int ret;
    uint32_t flags = 0;

    /* Parse root certificate and private key -> self signed certificate, root of trust */
    mbedtls_x509_crt_init(&crt_root);
    ret = mbedtls_x509_crt_parse(&crt_root, ec_root_ca_str, sizeof(ec_root_ca_str));
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);
    mbedtls_pk_init(&key_root);
    ret = mbedtls_pk_parse_key(&key_root, ec_root_key_str, sizeof(ec_root_key_str), NULL, 0, NULL, NULL);
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);

    /* Parse device certificate and its private key -> signed by trusted private key */
    mbedtls_x509_crt_init(&crt_device);
    ret = mbedtls_x509_crt_parse(&crt_device, ec_device_ca_str, sizeof(ec_device_ca_str));
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);
    mbedtls_pk_init(&key_device);
    ret = mbedtls_pk_parse_key(&key_device, ec_device_key_str, sizeof(ec_device_key_str), NULL, 0, NULL, NULL);
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);

    /* DEVICE SIDE START */

    /* Demonstrate that device will sign the challenge with its private hey */
    /* Device does the hash of the challenge -> whatever random value, with SHA-256 */
    for (size_t i = 0; i < sizeof(hash); ++i) {
        hash[i] = i;
    }

    /* Device signs the hash and sends signature to the host */
    ret = mbedtls_pk_sign(&key_device, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature, sizeof(signature),
                          &signature_len, fn_rng, NULL);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);

    /* DEVICE SIDE END */

    /* HOST SIDE START */

    /* Host receives certificate and signature (signed with private key) */
    /* Host does the certificate check, if it has been signed by manufacturing private key */
    ret = mbedtls_x509_crt_verify(&crt_device, &crt_root, NULL, NULL, &flags, NULL, NULL);
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);
    if (ret != 0) {
        printf("Invalid certificate. Hard error, potential clone detected!\r\n");
    }

    /* Verify signature at this point */
    ret = mbedtls_pk_verify(&crt_device.pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature, signature_len);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);
    if (ret != 0) {
        printf("Signature not signed by device private key. Hard error, potential clone detected!\r\n");
    }

    /* HOST SIDE END */

    return 1;
}