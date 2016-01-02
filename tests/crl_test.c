#include "tests.h"
#include "utils.h"
#include "x509.h"
#include "crl.h"

int crl_test(uasn1_key_t *key, uasn1_digest_t digest, char *name)
{
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);
    uasn1_item_t *cert, *dn;
    uasn1_item_t *revoked = uasn1_sequence_new(8);
    uasn1_item_t *tbs;
    FILE *f = NULL;
    char fname[64];

    sprintf(fname, "%s.der", name);
    uasn1_load_buffer(buffer, fname);
    cert = uasn1_decode(buffer);
    uasn1_buffer_free(buffer);
    dn = uasn1_x509_get_subject(uasn1_x509_get_tbs(cert));

    uasn1_crl_add_entry(revoked, uasn1_integer_new(5),
                        uasn1_get_generalized_time(-86400), NULL);
    uasn1_crl_add_entry(revoked, uasn1_integer_new(10),
                        uasn1_get_generalized_time(-86000),
                        uasn1_crl_reason(superseded));
    uasn1_crl_add_entry(revoked, uasn1_integer_new(10),
                        uasn1_get_generalized_time(-2 * 86400),
                        uasn1_crl_reason(keyCompromise));
    uasn1_crl_add_entry(revoked, uasn1_integer_new(63),
                        uasn1_get_generalized_time(-3 * 86400), NULL);

    tbs = uasn1_crl_tbs_new(uasn1_x509_algorithm(key, digest),
                            dn, uasn1_get_generalized_time(0),
                            uasn1_get_generalized_time(7 * 86400),
                            revoked, NULL);

	buffer = uasn1_buffer_new(64);
    uasn1_x509_sign(tbs, key, digest, buffer);
    sprintf(fname, "%s_crl.der", name);
    uasn1_write_buffer(buffer, fname);

    sprintf(fname, "%s_crl.pem", name);
    f = fopen(fname, "w");
    fprintf(f, "-----BEGIN CRL-----\n");
    uasn1_write_base64_buffer(buffer, f);
    fprintf(f, "-----END CRL-----\n");
    fclose(f);

    return 0;
}
