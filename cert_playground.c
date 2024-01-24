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
 * OEM certificate    -> self signed
 * Device certificate -> signed by device
 */

static uint8_t ec_oem_ca_str[] = {
#include "certificates/ec_oem.crt.hexarr"
    , 0};
static uint8_t ec_oem_key_str[] = {
#include "certificates/ec_oem.key.hexarr"
    , 0};
static uint8_t ec_oem_pubkey_str[] = {
#include "certificates/ec_oem_pub.key.hexarr"
    , 0};
static uint8_t ec_device_ca_str[] = {
#include "certificates/ec_device.crt.hexarr"
    , 0};
static uint8_t ec_device_key_str[] = {
#include "certificates/ec_device.key.hexarr"
    , 0};
static uint8_t ec_device_pubkey_str[] = {
#include "certificates/ec_device_pub.key.hexarr"
    , 0};

static mbedtls_x509_crt crt_oem;
static mbedtls_pk_context key_oem;
static mbedtls_pk_context pubkey_oem;
static mbedtls_x509_crt crt_device;
static mbedtls_pk_context key_device;
static mbedtls_pk_context pubkey_device;

static uint8_t hash_sent[32], hash_received[32];
static uint8_t signature[128];
static size_t signature_len;

static int
fn_rng(void* par, unsigned char* output, size_t len) {
    static uint32_t number;

    number *= (uint32_t)len;
    number += 0x12345F1A;
    for (size_t i = 0; i < len; ++i) {
        output[i] = (len * 2 + i - 1) ^ ((uint8_t)number);
    }
    return 0;
}

int
cert_playground(void) {
    int ret;
    uint32_t flags = 0;

    /* Parse oem certificate and private key -> self signed certificate, oem of trust */
    mbedtls_x509_crt_init(&crt_oem);
    ret = mbedtls_x509_crt_parse(&crt_oem, ec_oem_ca_str, sizeof(ec_oem_ca_str));
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);
    mbedtls_pk_init(&key_oem);
    ret = mbedtls_pk_parse_key(&key_oem, ec_oem_key_str, sizeof(ec_oem_key_str), NULL, 0, NULL, NULL);
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);
    mbedtls_pk_init(&pubkey_oem);
    ret = mbedtls_pk_parse_public_key(&pubkey_oem, ec_oem_pubkey_str, sizeof(ec_oem_pubkey_str));
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);

    /* Parse device certificate and its private key -> signed by trusted private key */
    mbedtls_x509_crt_init(&crt_device);
    ret = mbedtls_x509_crt_parse(&crt_device, ec_device_ca_str, sizeof(ec_device_ca_str));
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);
    mbedtls_pk_init(&key_device);
    ret = mbedtls_pk_parse_key(&key_device, ec_device_key_str, sizeof(ec_device_key_str), NULL, 0, NULL, NULL);
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);
    mbedtls_pk_init(&pubkey_device);
    ret = mbedtls_pk_parse_public_key(&pubkey_device, ec_device_pubkey_str, sizeof(ec_device_pubkey_str));
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);

    /* DEVICE SIDE START */

    /* Demonstrate that device will sign the challenge with its private hey */
    /* Device does the hash of the challenge -> whatever random value, with SHA-256 */
    for (size_t i = 0; i < sizeof(hash_sent); ++i) {
        hash_sent[i] = i;
    }

    /* Device signs the hash and sends signature to the host */
    ret = mbedtls_pk_sign(&key_device, MBEDTLS_MD_SHA256, hash_sent, sizeof(hash_sent), signature, sizeof(signature),
                          &signature_len, fn_rng, NULL);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);

    /* DEVICE SIDE END */

    /* HOST SIDE START */
    /* We received the hash, store it to the received variable */
    memcpy(hash_received, hash_sent, sizeof(hash_sent));

    /* Verify if hash has been signed by the private key of our device. Use pubkey for that */
    /* This is simple with public key only - nothing amazing */
    ret = mbedtls_pk_verify(&pubkey_device, MBEDTLS_MD_SHA256, hash_received, sizeof(hash_received), signature,
                            signature_len);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);

    /* Host receives certificate and signature (signed with private key) */
    /* Host does the certificate check, if it has been signed by manufacturing private key */
    ret = mbedtls_x509_crt_verify(&crt_device, &crt_oem, NULL, NULL, &flags, NULL, NULL);
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);
    if (ret != 0) {
        printf("Invalid certificate. Hard error, potential clone detected!\r\n");
    } else {
        /* Verify signature at this point */
        ret = mbedtls_pk_verify(&crt_device.pk, MBEDTLS_MD_SHA256, hash_received, sizeof(hash_received), signature,
                                signature_len);
        printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);
        if (ret != 0) {
            printf("Signature not signed by device private key. Hard error, potential clone detected!\r\n");
        }
    }

    /* Here all has to be freed, or it won't work indeed */
    mbedtls_pk_free(&key_oem);

    /* HOST SIDE END */

    return 1;
}
