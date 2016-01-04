/*
 * Copyright © 2015 Mathias Brossard
 */

#include "crypto.h"
#include "utils.h"

int uasn1_x509_sign(uasn1_item_t *tbs,
                    uasn1_key_t *key,
                    uasn1_digest_t digest,
                    uasn1_buffer_t *buffer)
{
    uasn1_buffer_t *buff = uasn1_buffer_new(64);
    uasn1_item_t *certificate = uasn1_sequence_new(3);
    uasn1_item_t *signature, *tbs2, *algoid;
    int rv;

    uasn1_encode(tbs, buff);

    tbs2 = uasn1_preencoded(buff);
    uasn1_add(certificate, tbs2);

    algoid = uasn1_x509_algorithm(key, digest);
    uasn1_add(certificate, algoid);

    signature = uasn1_key_x509_sign(key, digest, buff);
    uasn1_add(certificate, signature);

    rv = uasn1_encode(certificate, buffer);

    uasn1_free(certificate);
    uasn1_buffer_free(buff);
    return rv;
}
