/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "cryptoki.h"
#include "crypto.h"
#include "x509.h"
#include "pkix.h"
#include "utils.h"

#include <string.h>
#include <stdio.h>

int x509_test(uasn1_key_t *private, uasn1_key_t *public)
{
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);
    uasn1_item_t *dn = uasn1_sequence_new(2);
    uasn1_item_t *extensions = uasn1_sequence_new(1);
    uasn1_item_t *tbs, *public_key;
    unsigned int keyUsage = keyCertSign | cRLSign;
    FILE *f = NULL;

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
    uasn1_x509_add_ski(extensions, uasn1_false, public_key);

    /* Building the TBS */
    tbs = uasn1_x509_tbs_new
        (2,
         uasn1_integer_new(0x1),
         dn,
         uasn1_utc_time_new(notBefore, strlen(notBefore)),
         uasn1_utc_time_new(notAfter, strlen(notAfter)),
         dn,
         newASN1PublicKeyInfo(public_key),
         NULL,
         NULL,
         extensions);
 
    uasn1_x509_sign_new(tbs, private, UASN1_SHA1, buffer);

    uasn1_write_buffer(buffer, "test.der");

    f = fopen("test.pem", "w");
    fprintf(f, "-----BEGIN CERTIFICATE-----\n");
    uasn1_write_base64_buffer(buffer, f);
    fprintf(f, "-----END CERTIFICATE-----\n");
    fclose(f);

    uasn1_buffer_free(buffer);

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

    x509_test(rsa_prv, rsa_pub);

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        return rc;
    }

    return rc;
#endif
}
