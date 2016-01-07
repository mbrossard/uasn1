#include "tests.h"
#include "utils.h"
#include "tsa.h"

int tsa_request_test(uasn1_crypto_t *crypto, uasn1_digest_t digest, char *name)
{
    uasn1_buffer_t *buffer = uasn1_buffer_new(1024);
    uasn1_item_t *hash = uasn1_digest_octet_string(crypto, digest, buffer->buffer, buffer->size);
    uasn1_item_t *imprint = uasn1_tsa_imprint(digest, hash);
    uasn1_item_t *tsa_request = uasn1_tsa_request(imprint, NULL, NULL, NULL, NULL);
    char fname[64];

    uasn1_encode(tsa_request, buffer);
    sprintf(fname, "%s_tsa_req.der", name);
    uasn1_write_buffer(buffer, fname);
    uasn1_buffer_free(buffer);

    return 0;
}

int tsa_response_test(uasn1_digest_t digest, char *name, char *crt_path,
                      uasn1_crypto_t *crypto, uasn1_key_t *key)
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
                            uasn1_get_generalized_time(0),
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);

    response = uasn1_tsa_response(tstinfo, digest, uasn1_get_utc_time(0), crt, crypto, key);
    uasn1_encode(response, tsr);
    sprintf(fname, "%s_tsa_res.der", name);
    uasn1_write_buffer(tsr, fname);

    return 0;
}
