/*
 * Copyright © 2015 Mathias Brossard
 */

#include <string.h>

#include "crl.h"
#include "x509.h"

uasn1_item_t *uasn1_crl_tbs_new(uasn1_item_t *signature,
                                uasn1_item_t *issuer,
                                uasn1_item_t *thisUpdate,
                                uasn1_item_t *nextUpdate,
                                uasn1_item_t *revoked,
                                uasn1_item_t *extensions)
{
    uasn1_item_t *tbs = uasn1_sequence_new(7);

    uasn1_add(tbs, uasn1_integer_new(2));
    uasn1_add(tbs, signature);
    uasn1_add(tbs, issuer);
    uasn1_add(tbs, thisUpdate);
    uasn1_add(tbs, nextUpdate);
    uasn1_add(tbs, revoked);
    uasn1_add_tagged(tbs, extensions, uasn1_context_specific_tag,
                     0, uasn1_explicit_tag);

    return tbs;
}

void uasn1_crl_add_entry(uasn1_item_t *list, uasn1_item_t *serial,
                         uasn1_item_t *date, uasn1_item_t *extensions)
{
    uasn1_item_t *revoked = uasn1_sequence_new(3);

    uasn1_add(revoked, serial);
    uasn1_add(revoked, date);
    uasn1_add(revoked, extensions);
    uasn1_add(list, revoked);
}

uasn1_item_t *uasn1_crl_reason(uasn1_crl_reason_t reason)
{
    uasn1_item_t *crlext = uasn1_sequence_new(1);
    uasn1_add_x509_extension(crlext, "cRLReason",
                             uasn1_false, uasn1_enumerated_new(reason));
    return crlext;
}
