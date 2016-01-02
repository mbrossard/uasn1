/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "cryptoki.h"
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
    CK_SLOT_ID        *pslots = NULL;
    CK_ULONG          nslots, islot, pin_len = strlen(pin);
    CK_RV             rc;


    rc = pkcs11_load_init(NULL, dir, &funcs);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_check_slot(funcs, slot);
    if (rc != CKR_OK) {
        return rc;
    }

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

    uasn1_key_t *rsa_prv = uasn1_load_pkcs11_key(funcs, slot, CKO_PRIVATE_KEY, rsa_label);
    uasn1_key_t *rsa_pub = uasn1_load_pkcs11_key(funcs, slot, CKO_PUBLIC_KEY, rsa_label);
    uasn1_key_t *ec_prv = uasn1_load_pkcs11_key(funcs, slot, CKO_PRIVATE_KEY, ec_label);
    uasn1_key_t *ec_pub = uasn1_load_pkcs11_key(funcs, slot, CKO_PUBLIC_KEY, ec_label);

    if(!(rsa_prv && rsa_pub && ec_prv && ec_pub)) {
        printf("RSA private (%p), public (%p)\n", rsa_prv, rsa_pub);
        printf("EC private (%p), public (%p)\n", ec_prv, ec_pub);
        return -1;
    }

    request_test(rsa_prv, rsa_pub, UASN1_SHA1,   "tests/rsa_sha1_csr");
    request_test(rsa_prv, rsa_pub, UASN1_SHA256, "tests/rsa_sha256_csr");
    request_test(ec_prv,  ec_pub,  UASN1_SHA256, "tests/ec_csr");

    x509_self_test(rsa_prv, rsa_pub, UASN1_SHA1,   "tests/rsa_sha1_ca");
    x509_self_test(rsa_prv, rsa_pub, UASN1_SHA256, "tests/rsa_sha256_ca");
    x509_self_test(ec_prv,  ec_pub,  UASN1_SHA256, "tests/ec_ca");

    x509_sign_test(rsa_prv, rsa_pub, UASN1_SHA1,   "tests/rsa_sha1_ca",   "tests/tsa_rsa1_crt");
    x509_sign_test(rsa_prv, rsa_pub, UASN1_SHA256, "tests/rsa_sha256_ca", "tests/tsa_rsa2_crt");
    x509_sign_test(ec_prv,  ec_pub,  UASN1_SHA256, "tests/ec_ca",         "tests/tsa_ec_crt");
    crl_test(rsa_prv, UASN1_SHA1,   "tests/rsa1_ca");
    crl_test(rsa_prv, UASN1_SHA256, "tests/rsa2_ca");
    crl_test(ec_prv,  UASN1_SHA256, "tests/ec_ca");

    x509_sign_test(rsa_prv, rsa_pub, UASN1_SHA1,   "tests/rsa_sha1_ca",   "tests/ocsp_rsa1_crt");
    x509_sign_test(rsa_prv, rsa_pub, UASN1_SHA256, "tests/rsa_sha256_ca", "tests/ocsp_rsa2_crt");
    x509_sign_test(ec_prv,  ec_pub,  UASN1_SHA256, "tests/ec_ca",         "tests/ocsp_ec_crt");

    ocsp_request_test(rsa_pub, "tests/rsa_sha1_ca",   "tests/ocsp_rsa1_crt");
    ocsp_request_test(rsa_pub, "tests/rsa_sha256_ca", "tests/ocsp_rsa2_crt");
    ocsp_request_test(ec_pub,  "tests/ec_ca",         "tests/ocsp_ec_crt");

    ocsp_response_test(rsa_prv, UASN1_SHA1,   "tests/ocsp_rsa1_crt");
    ocsp_response_test(rsa_prv, UASN1_SHA256, "tests/ocsp_rsa2_crt");
    ocsp_response_test(ec_prv,  UASN1_SHA256, "tests/ocsp_ec_crt");

    tsa_request_test(funcs, slot, UASN1_SHA1,   "tests/rsa1");
    tsa_request_test(funcs, slot, UASN1_SHA256, "tests/rsa2");
    tsa_request_test(funcs, slot, UASN1_SHA256, "tests/ec");

    tsa_response_test(UASN1_SHA1,   "tests/rsa1", "tests/tsa_rsa1_crt", rsa_prv);
    tsa_response_test(UASN1_SHA256, "tests/rsa2", "tests/tsa_rsa2_crt", rsa_prv);
    tsa_response_test(UASN1_SHA256, "tests/ec",   "tests/tsa_ec_crt",   ec_prv);

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        return rc;
    }

    return rc;
#endif
}
