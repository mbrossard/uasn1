/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "crypto.h"
#include "crypto/key.h"
#include "tests.h"
#include "x509.h"
#include "pkix.h"
#include "utils.h"
#include "tsa.h"
#include "request.h"

#include <string.h>
#include <stdio.h>

int main(int argc, char **argv)
{
#ifndef DEFAULT_PKCS11_MODULE
    printf("Compiled without path to NSS module\n");
    return 0;
#else
    char              *pin = "Vl0RJlAKiUMf";
    char              *label = "UASN1";
    char              *dir = "tests";
    CK_ULONG          slot = 2;
    CK_UTF8CHAR_PTR   rsa_label = (CK_UTF8CHAR_PTR)"rsa2048";
    CK_UTF8CHAR_PTR   ec_label = (CK_UTF8CHAR_PTR)"ec256";

    CK_SESSION_HANDLE h_session;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_ULONG          pin_len = strlen(pin);
    CK_RV             rc;


    rc = pkcs11_load_init(NULL, dir, &funcs);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_check_slot(funcs, slot);
    if (rc != CKR_OK) {
        return rc;
    }

    fprintf(stderr, "Initialize token\n");
    rc = pkcs11_init_token(funcs, slot, (CK_UTF8CHAR_PTR) label,
                           (CK_UTF8CHAR_PTR) pin, pin_len);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_login_session(funcs, slot, &h_session,
                              CK_TRUE, CKU_USER, (CK_UTF8CHAR_PTR)pin, pin_len);
    if (rc != CKR_OK) {
        return rc;
    }

    fprintf(stderr, "Genereate keys\n");
    rc = pkcs11_generate_key_pair(funcs, h_session, CKK_RSA, 2048,
                                  rsa_label, NULL, NULL);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_generate_key_pair(funcs, h_session, CKK_EC, 256,
                                  ec_label, NULL, NULL);
    if (rc != CKR_OK) {
        return rc;
    }

    fprintf(stderr, "Load keys\n");
    uasn1_crypto_t *crypto = uasn1_pkcs11_crypto(funcs, slot);
    uasn1_key_t *rsa_prv = uasn1_key_load(crypto, UASN1_PRIVATE, (char *)rsa_label);
    uasn1_key_t *rsa_pub = uasn1_key_load(crypto, UASN1_PUBLIC,  (char *)rsa_label);
    uasn1_key_t *ec_prv =  uasn1_key_load(crypto, UASN1_PRIVATE, (char *)ec_label);
    uasn1_key_t *ec_pub =  uasn1_key_load(crypto, UASN1_PUBLIC,  (char *)ec_label);

    if(!(rsa_prv && rsa_pub && ec_prv && ec_pub)) {
        printf("RSA private (%p), public (%p)\n", (void *)rsa_prv, (void *)rsa_pub);
        printf("EC private (%p), public (%p)\n", (void *)ec_prv, (void *)ec_pub);
        return -1;
    }

    fprintf(stderr, "Crete certificate requests\n");
    request_test(rsa_prv, rsa_pub, UASN1_SHA1,   "tests/rsa1_csr");
    request_test(rsa_prv, rsa_pub, UASN1_SHA256, "tests/rsa2_csr");
    request_test(ec_prv,  ec_pub,  UASN1_SHA256, "tests/ec_csr");

    fprintf(stderr, "Crete self-signed certificates\n");
    x509_self_test(rsa_prv, rsa_pub, UASN1_SHA1,   "tests/rsa1_ca");
    x509_self_test(rsa_prv, rsa_pub, UASN1_SHA256, "tests/rsa2_ca");
    x509_self_test(ec_prv,  ec_pub,  UASN1_SHA256, "tests/ec_ca");

    fprintf(stderr, "Crete certificate revocation lists\n");
    crl_test(rsa_prv, UASN1_SHA1,   "tests/rsa1_ca");
    crl_test(rsa_prv, UASN1_SHA256, "tests/rsa2_ca");
    crl_test(ec_prv,  UASN1_SHA256, "tests/ec_ca");

    fprintf(stderr, "Sign certificates\n");
    x509_sign_test(rsa_prv, rsa_pub, UASN1_SHA1,   "tests/rsa1_ca", "tests/tsa_rsa1_crt");
    x509_sign_test(rsa_prv, rsa_pub, UASN1_SHA256, "tests/rsa2_ca", "tests/tsa_rsa2_crt");
    x509_sign_test(ec_prv,  ec_pub,  UASN1_SHA256, "tests/ec_ca",   "tests/tsa_ec_crt");

    x509_sign_test(rsa_prv, rsa_pub, UASN1_SHA1,   "tests/rsa1_ca", "tests/ocsp_rsa1_crt");
    x509_sign_test(rsa_prv, rsa_pub, UASN1_SHA256, "tests/rsa2_ca", "tests/ocsp_rsa2_crt");
    x509_sign_test(ec_prv,  ec_pub,  UASN1_SHA256, "tests/ec_ca",   "tests/ocsp_ec_crt");

    fprintf(stderr, "Create OCSP requests\n");
    ocsp_request_test(crypto, "tests/rsa1_ca", "tests/ocsp_rsa1_crt");
    ocsp_request_test(crypto, "tests/rsa2_ca", "tests/ocsp_rsa2_crt");
    ocsp_request_test(crypto, "tests/ec_ca",   "tests/ocsp_ec_crt");

    fprintf(stderr, "Sign OCSP responses\n");
    ocsp_response_test(rsa_prv, UASN1_SHA1,   "tests/ocsp_rsa1_crt");
    ocsp_response_test(rsa_prv, UASN1_SHA256, "tests/ocsp_rsa2_crt");
    ocsp_response_test(ec_prv,  UASN1_SHA256, "tests/ocsp_ec_crt");

    fprintf(stderr, "Create TSA requests\n");
    tsa_request_test(crypto, UASN1_SHA1,   "tests/rsa1");
    tsa_request_test(crypto, UASN1_SHA256, "tests/rsa2");
    tsa_request_test(crypto, UASN1_SHA256, "tests/ec");

    fprintf(stderr, "Sign TSA responses\n");
    tsa_response_test(UASN1_SHA1,   "tests/rsa1", "tests/tsa_rsa1_crt", crypto, rsa_prv);
    tsa_response_test(UASN1_SHA256, "tests/rsa2", "tests/tsa_rsa2_crt", crypto, rsa_prv);
    tsa_response_test(UASN1_SHA256, "tests/ec",   "tests/tsa_ec_crt",   crypto, ec_prv);

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        return rc;
    }

    return rc;
#endif
}
