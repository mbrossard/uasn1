/*
 * Copyright © 2015 Mathias Brossard
 */

#include <stdlib.h>
#include <string.h>

#include "uasn1.h"
#include "oids.h"
#include "x509.h"

uasn1_item_t *uasn1_request_tbs_new(uasn1_item_t *subject,
                                    uasn1_item_t *public,
                                    uasn1_item_t *attributes)
{
    uasn1_item_t *seq = uasn1_sequence_new(4);

    uasn1_add(seq, uasn1_integer_new(0));
    uasn1_add(seq, subject);
    uasn1_add(seq, public);
    uasn1_add_tagged(seq, attributes, uasn1_context_specific_tag,
                     0, uasn1_implicit_tag);

    return seq;
}
