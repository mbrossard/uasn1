#include "tests.h"
#include "utils.h"
#include "pkix.h"
#include "x509.h"
#include "request.h"

#include <string.h>

int x509_self_test(uasn1_key_t *private, uasn1_key_t *public,
                   uasn1_digest_t digest, char *name)
{
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);
    uasn1_item_t *dn = uasn1_sequence_new(2);
    uasn1_item_t *extensions = uasn1_sequence_new(1);
    uasn1_item_t *tbs;
    unsigned int keyUsage = keyCertSign | cRLSign;
    FILE *f = NULL;
    char fname[64];
    uasn1_item_t *notBefore = uasn1_get_utc_time(0);
    uasn1_item_t *notAfter = uasn1_get_utc_time(365 * 86400);


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
         notBefore,
         notAfter,
         dn,
         uasn1_key_get_asn1_public_key_info(public),
         NULL,
         NULL,
         extensions);
 
    uasn1_x509_sign(tbs, private, digest, buffer);

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

int x509_sign_test(uasn1_key_t *private, uasn1_key_t *public,
                   uasn1_digest_t digest, char *ca, char *name)
{
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);
    uasn1_item_t *dn_subject = uasn1_sequence_new(2), *dn_issuer;
    uasn1_item_t *extensions = uasn1_sequence_new(1);
    uasn1_item_t *ca_crt, *tbs;
    unsigned int keyUsage = digitalSignature;
    FILE *f = NULL;
    char fname[64];
    uasn1_buffer_t *ca_buf = uasn1_buffer_new(64);

    sprintf(fname, "%s.der", ca);
	uasn1_load_buffer(ca_buf, fname);
    ca_crt = uasn1_decode(ca_buf);
    dn_issuer = uasn1_get(uasn1_get(ca_crt, 0), 3);

    /* Building DN */
    uasn1_add(dn_subject, uasn1_dn_element("commonName", "Test"));
    uasn1_add(dn_subject, uasn1_dn_element("organizationName", name));

    /* Key Usage */
    uasn1_x509_add_key_usage(extensions, uasn1_true, keyUsage);

    /* Basic Constraints */
    uasn1_x509_add_basic_constraints(extensions, uasn1_true,
                                     uasn1_false, uasn1_false, 0);

    /* Extended Key Usage */
    if(strncmp(name, "tests/tsa", 10) == 0) {
        char *usages[] = { "timeStamping", NULL };
        uasn1_x509_add_ext_key_usage(extensions, uasn1_true, usages);
    } else {
        char *usages[] = { "ocspSigning", NULL };
        uasn1_x509_add_ext_key_usage(extensions, uasn1_false, usages);
    }

    /* Subject Key Identifier */
    uasn1_x509_add_ski(extensions, uasn1_false, uasn1_key_get_key_identifier(public));

    /* Authority Key Identifier */
    uasn1_x509_add_aki(extensions, uasn1_false, uasn1_key_get_key_identifier(public));

    /* Building the TBS */
    tbs = uasn1_x509_tbs_new
        (2,
         uasn1_integer_new(0x1),
         uasn1_x509_algorithm(public, digest),
         dn_issuer,
         uasn1_get_utc_time(0),
         uasn1_get_utc_time(364 * 86400),
         dn_subject,
         uasn1_key_get_asn1_public_key_info(public),
         NULL,
         NULL,
         extensions);
 
    uasn1_x509_sign(tbs, private, digest, buffer);

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
 
    uasn1_x509_sign(tbs, private, digest, buffer);

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
