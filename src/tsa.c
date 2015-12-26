/*
 * Copyright © 2015 Mathias Brossard
 */

#include "tsa.h"
#include "uasn1.h"

uasn1_item_t *uasn1_tsa_imprint(uasn1_digest_t digest,
                                uasn1_item_t *hash)
{
    uasn1_item_t *imprint = uasn1_sequence_new(2);
    uasn1_item_t *algoid = uasn1_sequence_new(2);
    uasn1_item_t *oid = uasn1_digest_oid(digest);

    uasn1_add(algoid, oid);
    uasn1_add(algoid, uasn1_item_new(uasn1_null_type));
    uasn1_add(imprint, algoid);
    uasn1_add(imprint, hash);
    return imprint;
}

uasn1_item_t *uasn1_tsa_request(uasn1_item_t *imprint,
                                uasn1_item_t *policy,
                                uasn1_item_t *nonce,
                                uasn1_item_t *certReq,
                                uasn1_item_t *extensions)
{
    uasn1_item_t *seq = uasn1_sequence_new(6);
    uasn1_add(seq, uasn1_integer_new(1));
    uasn1_add(seq, imprint);
    if(policy) {
        uasn1_add(seq, policy);
    }
    if(nonce) {
        uasn1_add(seq, nonce);
    }
    if(certReq) {
        uasn1_add(seq, certReq);
    }
    if(extensions) {
        uasn1_add_tagged(seq, extensions, uasn1_context_specific_tag,
                         0, uasn1_explicit_tag);
    }
    return seq;
}
