/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "cryptoki.h"
#include "crypto.h"
#include "x509.h"
#include "pkix.h"
#include "utils.h"
#include "ocsp.h"
#include "tsa.h"
#include "request.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

uasn1_item_t *getGeneralizedTime()
{
    time_t t = time(NULL);
    struct tm *st = localtime(&t);
    unsigned char g[16];
    sprintf((char *)g, "%04d%02d%02d%02d%02d%02dZ",
            (st->tm_year + 1900) % 10000,
            st->tm_mon % 100,
            st->tm_mday % 100,
            st->tm_hour % 100,
            st->tm_min % 100,
            st->tm_sec % 100);

    return uasn1_generalized_time_new(g, 15);
}

uasn1_item_t *getUtcTime()
{
    time_t t = time(NULL);
    struct tm *st = gmtime(&t);
    unsigned char g[16];
    sprintf((char *)g, "%02d%02d%02d%02d%02d%02dZ",
            st->tm_year % 100,
            st->tm_mon + 1 % 100,
            st->tm_mday % 100,
            st->tm_hour % 100,
            st->tm_min % 100,
            st->tm_sec % 100);

    return uasn1_utc_time_new(g, 13);
}

int x509_test(uasn1_key_t *private, uasn1_key_t *public, uasn1_digest_t digest, char *name)
{
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);
    uasn1_item_t *dn = uasn1_sequence_new(2);
    uasn1_item_t *extensions = uasn1_sequence_new(1);
    uasn1_item_t *tbs, *public_key;
    unsigned int keyUsage = keyCertSign | cRLSign;
    FILE *f = NULL;
    char fname[64];

    char *notBefore = "150101080001Z";
    char *notAfter =  "160101080001Z";

    public_key = uasn1_key_get_asn1_public_key(public);

    /* Building DN */
    uasn1_add(dn, uasn1_dn_element("commonName", "Test"));
    uasn1_add(dn, uasn1_dn_element("organizationName", "CA"));

    /* Key Usage */
    uasn1_x509_add_key_usage(extensions, uasn1_true, keyUsage);

    /* Basic Constraints */
    uasn1_x509_add_basic_constraints(extensions, uasn1_true, uasn1_true, uasn1_true, 3);

    /* Subject Key Identifier */
    uasn1_x509_add_ski(extensions, uasn1_false, uasn1_key_get_key_identifier(public));

    /* Authority Key Identifier */
    uasn1_x509_add_aki(extensions, uasn1_false, uasn1_key_get_key_identifier(public));

    /* Building the TBS */
    tbs = uasn1_x509_tbs_new
        (2,
         uasn1_integer_new(0x1),
         uasn1_x509_algorithm(public, digest),
         dn,
         uasn1_utc_time_new(notBefore, strlen(notBefore)),
         uasn1_utc_time_new(notAfter, strlen(notAfter)),
         dn,
         uasn1_key_get_asn1_public_key_info(public),
         NULL,
         NULL,
         extensions);
 
    uasn1_x509_sign_new(tbs, private, digest, buffer);

    sprintf(fname, "%s.der", name);
    uasn1_write_buffer(buffer, fname);

    sprintf(fname, "%s.pem", name);
    f = fopen(fname, "w");
    fprintf(f, "-----BEGIN CERTIFICATE-----\n");
    uasn1_write_base64_buffer(buffer, f);
    fprintf(f, "-----END CERTIFICATE-----\n");
    fclose(f);

    uasn1_buffer_free(buffer);

    return 0;
}

int request_test(uasn1_key_t *private, uasn1_key_t *public, uasn1_digest_t digest, char *name)
{
    uasn1_buffer_t *buffer = uasn1_buffer_new(1024);
    uasn1_item_t *dn = uasn1_sequence_new(2);
    uasn1_item_t *set = uasn1_set_new(1);
    uasn1_item_t *tbs = NULL;
    FILE *f = NULL;
    char fname[64];

    /* Building DN */
    uasn1_add(dn, uasn1_dn_element("commonName", "Test"));
    uasn1_add(dn, uasn1_dn_element("organizationName", "CA"));

    /* Building the TBS */
    tbs = uasn1_request_tbs_new
        (dn,
         uasn1_key_get_asn1_public_key_info(public),
         set);
 
    uasn1_x509_sign_new(tbs, private, digest, buffer);

    sprintf(fname, "%s.der", name);
    uasn1_write_buffer(buffer, fname);

    sprintf(fname, "%s.pem", name);
    f = fopen(fname, "w");
    fprintf(f, "-----BEGIN CERTIFICATE REQUEST-----\n");
    uasn1_write_base64_buffer(buffer, f);
    fprintf(f, "-----END CERTIFICATE REQUEST-----\n");
    fclose(f);

    uasn1_buffer_free(buffer);

    return 0;
}

int ocsp_request_test(uasn1_key_t *key, char *name)
{
    uasn1_item_t *list = uasn1_sequence_new(1);
    uasn1_item_t *tbs;
    uasn1_item_t *req;
    uasn1_buffer_t *crt1 = uasn1_buffer_new(64);
    uasn1_buffer_t *crt2 = uasn1_buffer_new(64);
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);
    char fname[64];

    sprintf(fname, "%s.der", name);
	uasn1_load_buffer(crt1, fname);
	uasn1_load_buffer(crt2, fname);

	uasn1_add(list, uasn1_ocsp_single_request(key, crt1, crt2, NULL));

	req = uasn1_ocsp_request(0, NULL, list, NULL);

    uasn1_encode(req, buffer);

    sprintf(fname, "%s_ocsp_req.der", name);
    uasn1_write_buffer(buffer, fname);

    uasn1_buffer_free(buffer);
    return 0;
}

int tsa_request_test(CK_FUNCTION_LIST_PTR funcs, CK_SLOT_ID slot,
                     uasn1_digest_t digest, char *name)
{
    uasn1_buffer_t *buffer = uasn1_buffer_new(1024);
    uasn1_item_t *hash = uasn1_digest_octet_string(funcs, slot, digest,
                                                   buffer->buffer, buffer->size);
    uasn1_item_t *imprint = uasn1_tsa_imprint(digest, hash);
    uasn1_item_t *tsa_request = uasn1_tsa_request(imprint, NULL, NULL, NULL, NULL);
    char fname[64];

    uasn1_encode(tsa_request, buffer);
    sprintf(fname, "%s_tsa_req.der", name);
    uasn1_write_buffer(buffer, fname);
    uasn1_buffer_free(buffer);

    return 0;
}

int tsa_response_test(uasn1_digest_t digest, char *name, char *crt_path, uasn1_key_t *key)
{
    unsigned int foo[7] = { 1, 2, 3, 4, 5, 6, 7 };
    uasn1_buffer_t *crt = uasn1_buffer_new(1024);
    uasn1_buffer_t *tsq = uasn1_buffer_new(128);
    uasn1_buffer_t *tsr = uasn1_buffer_new(1024);
    uasn1_item_t *req, *tstinfo, *response;
    char fname[64];

    sprintf(fname, "%s_tsa_req.der", name);
    uasn1_load_buffer(tsq, fname);
    sprintf(fname, "%s.der", crt_path);
    uasn1_load_buffer(crt, fname);

    req = uasn1_decode(tsq);
    tstinfo = uasn1_tstinfo(uasn1_oid_new(foo, 7),
                            req->value.list.elements[1],
                            uasn1_integer_new(1),
                            getGeneralizedTime(),
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);

    response = uasn1_tsa_response(tstinfo, digest, getUtcTime(), crt, key);
    uasn1_encode(response, tsr);
    sprintf(fname, "%s_tsa_res.der", name);
    uasn1_write_buffer(tsr, fname);

    return 0;
}

int main(int argc, char **argv)
{
#ifndef DEFAULT_PKCS11_MODULE
    printf("Compiled without path to NSS module\n");
    return 0;
#else
    char              *pin = "Vl0RJlAKiUMf";
    char              *label = "UASN1";
    char              *dir = ".";
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

    request_test(rsa_prv, rsa_pub, UASN1_SHA1, "tests/rsa_sha1_csr");
    request_test(rsa_prv, rsa_pub, UASN1_SHA256, "tests/rsa_sha256_csr");
    request_test(ec_prv, ec_pub, UASN1_SHA256, "tests/ec_csr");

    x509_test(rsa_prv, rsa_pub, UASN1_SHA1, "tests/rsa_sha1_crt");
    x509_test(rsa_prv, rsa_pub, UASN1_SHA256, "tests/rsa_sha256_crt");
    x509_test(ec_prv, ec_pub, UASN1_SHA256, "tests/ec_crt");

    ocsp_request_test(rsa_pub, "tests/rsa_sha1_crt");
    ocsp_request_test(rsa_pub, "tests/rsa_sha256_crt");
    ocsp_request_test(ec_pub,  "tests/ec_crt");

    tsa_request_test(funcs, slot, UASN1_SHA1,   "tests/sha1");
    tsa_request_test(funcs, slot, UASN1_SHA256, "tests/sha256");
    tsa_request_test(funcs, slot, UASN1_SHA256, "tests/sha256_ec");

    tsa_response_test(UASN1_SHA1,   "tests/sha1",       "tests/rsa_sha1_crt",   rsa_prv);
    tsa_response_test(UASN1_SHA256, "tests/sha256",     "tests/rsa_sha256_crt", rsa_prv);
    tsa_response_test(UASN1_SHA256, "tests/sha256_ec",  "tests/ec_crt",         ec_prv);

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        return rc;
    }

    return rc;
#endif
}
