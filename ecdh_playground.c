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
#include "mbedtls/ecdh.h"

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

static int
fn_rng(void* par, unsigned char* output, size_t len) {
    static uint32_t number;

    (void)par;

    number *= (uint32_t)len;
    number += 0x12345F1A;
    for (size_t i = 0; i < len; ++i) {
        output[i] = (len * 2 + i - 1) ^ ((uint8_t)number);
    }
    return 0;
}

int
ecdh_playground(void) {
    int ret;
    uint32_t flags = 0;

    mbedtls_x509_crt x509_crt_oem;
    mbedtls_pk_context pk_key_oem;
    mbedtls_x509_crt x509_crt_device;
    mbedtls_pk_context pk_key_device;
    mbedtls_ecdh_context ecdh_oem;
    mbedtls_ecdh_context ecdh_device;
    mbedtls_ecp_group grp_A;
    mbedtls_ecp_group grp_B;
    mbedtls_mpi priv_key_A;
    mbedtls_mpi priv_key_B;
    mbedtls_mpi shared_secret_A;
    mbedtls_mpi shared_secret_B;
    mbedtls_ecp_point pub_key_A;
    mbedtls_ecp_point pub_key_B;

    /* Parse oem certificate and private key -> self signed certificate, oem of trust */
    mbedtls_x509_crt_init(&x509_crt_oem);
    mbedtls_pk_init(&pk_key_oem);
    mbedtls_x509_crt_init(&x509_crt_device);
    mbedtls_pk_init(&pk_key_device);

    /* Parse first device data */
    ret = mbedtls_x509_crt_parse(&x509_crt_oem, ec_oem_ca_str, sizeof(ec_oem_ca_str));
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);
    ret = mbedtls_pk_parse_key(&pk_key_oem, ec_oem_key_str, sizeof(ec_oem_key_str), NULL, 0, NULL, NULL);
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);

    /* Parse second device data */
    ret = mbedtls_x509_crt_parse(&x509_crt_device, ec_device_ca_str, sizeof(ec_device_ca_str));
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);
    ret = mbedtls_pk_parse_key(&pk_key_device, ec_device_key_str, sizeof(ec_device_key_str), NULL, 0, NULL, NULL);
    printf("RET: %d, line: %d, flags: %u\r\n", (int)ret, (int)__LINE__, (uint32_t)flags);

    /* Try to use parsed values here, let's see how it fails ;) */

    /* Let's start ECDH playground now */
    mbedtls_ecdh_init(&ecdh_oem);
    mbedtls_ecdh_init(&ecdh_device);
    mbedtls_ecp_group_init(&grp_A);
    mbedtls_ecp_group_init(&grp_B);
    mbedtls_mpi_init(&priv_key_A);
    mbedtls_mpi_init(&priv_key_B);
    mbedtls_ecp_point_init(&pub_key_A);
    mbedtls_ecp_point_init(&pub_key_B);
    mbedtls_mpi_init(&shared_secret_A);
    mbedtls_mpi_init(&shared_secret_B);

    /* Setup for both sides */
    ret = mbedtls_ecdh_setup(&ecdh_device, MBEDTLS_ECP_DP_SECP256R1);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);
    ret = mbedtls_ecdh_setup(&ecdh_device, MBEDTLS_ECP_DP_SECP256R1);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);

#if 1
    /* Export values from the certificate -> only group and public keys will work */
    /* Private key is not part of the certificate part */
    /* Use it as parameter to avoid runtime issue, but ignore priv_key_X values */
    /* Device A = OEM */
    /* Device B = Client device */
    ret = mbedtls_ecp_export(mbedtls_pk_ec(x509_crt_oem.pk), &grp_A, &priv_key_A, &pub_key_A);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);
    ret = mbedtls_ecp_export(mbedtls_pk_ec(x509_crt_device.pk), &grp_B, &priv_key_B, &pub_key_B);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);

    /* Here we have to load private keys */
    const mbedtls_ecp_keypair* k_A = mbedtls_pk_ec(pk_key_oem);
    const mbedtls_ecp_keypair* k_B = mbedtls_pk_ec(pk_key_device);
    mbedtls_mpi_copy(&priv_key_A, &k_A->MBEDTLS_PRIVATE(d));
    mbedtls_mpi_copy(&priv_key_B, &k_B->MBEDTLS_PRIVATE(d));

#else
    /* Load ECP parameters, then generate public/private key pairs */
    ret = mbedtls_ecp_group_load(&grp_A, MBEDTLS_ECP_DP_SECP256R1);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);
    ret = mbedtls_ecdh_gen_public(&grp_A, &priv_key_A, &pub_key_A, fn_rng, NULL);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);

    /* Different device */
    ret = mbedtls_ecp_group_load(&grp_B, MBEDTLS_ECP_DP_SECP256R1);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);
    ret = mbedtls_ecdh_gen_public(&grp_B, &priv_key_B, &pub_key_B, fn_rng, NULL);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);
#endif

    /* Now compute twice... */
    /* Alice side */
    ret = mbedtls_ecdh_compute_shared(&grp_A, &shared_secret_A, &pub_key_B, &priv_key_A, fn_rng, NULL);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);
    /* Bob side */
    ret = mbedtls_ecdh_compute_shared(&grp_B, &shared_secret_B, &pub_key_A, &priv_key_B, fn_rng, NULL);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);

    ret = mbedtls_mpi_cmp_mpi(&shared_secret_A, &shared_secret_B);
    printf("RET: %d, line: %d\r\n", (int)ret, (int)__LINE__);

    mbedtls_ecdh_free(&ecdh_oem);
    mbedtls_ecdh_free(&ecdh_device);
    mbedtls_ecp_group_free(&grp_A);
    mbedtls_ecp_group_free(&grp_B);
    mbedtls_mpi_free(&priv_key_A);
    mbedtls_mpi_free(&priv_key_B);
    mbedtls_ecp_point_free(&pub_key_A);
    mbedtls_ecp_point_free(&pub_key_B);
    mbedtls_mpi_free(&shared_secret_A);
    mbedtls_mpi_free(&shared_secret_B);

    /* Here all has to be freed, or it won't work indeed */
    mbedtls_pk_free(&pk_key_oem);
    mbedtls_pk_free(&pk_key_device);
    mbedtls_x509_crt_free(&x509_crt_oem);
    mbedtls_x509_crt_free(&x509_crt_device);

    /* HOST SIDE END */

    return 1;
}
