/*
 * Copyright © 2015 Mathias Brossard
 */

#include <stdlib.h>
#include <string.h>

#include "uasn1.h"
#include "oids.h"
#include "x509.h"

uasn1_item_t *uasn1_pki_sha1_rsa_algo()
{
    uasn1_item_t *algoid = uasn1_sequence_new(2);
    unsigned int sha1withRSAEncryption[7] = { 1, 2, 840, 113549, 1, 1, 5 };

    /* building Signature OID */
    uasn1_add(algoid, uasn1_oid_new(sha1withRSAEncryption, 7));
    uasn1_add(algoid, uasn1_item_new(uasn1_null_type));
    return algoid;
}

uasn1_item_t *uasn1_x509_tbs_new(int version,
                                 uasn1_item_t *serial,
                                 uasn1_item_t *algoid,
                                 uasn1_item_t *issuer,
                                 uasn1_item_t *notBefore,
                                 uasn1_item_t *notAfter,
                                 uasn1_item_t *subject,
                                 uasn1_item_t *publickey,
                                 uasn1_item_t *issuerUniqueID,
                                 uasn1_item_t *subjectUniqueID,
                                 uasn1_item_t *extensions)
{
    uasn1_item_t *seq = uasn1_sequence_new(8);
    uasn1_item_t *validity = uasn1_sequence_new(2);

    /* Building algorithm ID */
    uasn1_add(validity, notBefore);
    uasn1_add(validity, notAfter);

    if(version) {
        uasn1_add(seq, uasn1_set_tag(uasn1_integer_new(version),
                                     uasn1_context_specific_tag, 0, uasn1_explicit_tag));
    }
    uasn1_add(seq, serial);
    uasn1_add(seq, algoid);
    uasn1_add(seq, issuer);
    uasn1_add(seq, validity);
    uasn1_add(seq, subject);
    uasn1_add(seq, publickey);
    uasn1_add_tagged(seq,issuerUniqueID, uasn1_context_specific_tag,
                     1, uasn1_implicit_tag);
    uasn1_add_tagged(seq, subjectUniqueID, uasn1_context_specific_tag,
                     2, uasn1_implicit_tag);
    uasn1_add_tagged(seq, extensions, uasn1_context_specific_tag,
                     3, uasn1_explicit_tag);

    return seq;
}

uasn1_item_t *uasn1_x509_get_tbs(uasn1_item_t *certificate)
{
    return certificate->value.list.elements[0];
}

uasn1_item_t *uasn1_x509_get_serial(uasn1_item_t *tbs)
{
    /* FIXME Only valid for X509v3 TBS */
    return tbs->value.list.elements[1];
}

uasn1_item_t *uasn1_x509_get_issuer(uasn1_item_t *tbs)
{
    /* FIXME Only valid for X509v3 TBS */
    return tbs->value.list.elements[3];
}

uasn1_item_t *uasn1_x509_get_subject(uasn1_item_t *tbs)
{
    /* FIXME Only valid for X509v3 TBS */
    return tbs->value.list.elements[5];
}

uasn1_item_t *uasn1_x509_get_pubkey(uasn1_item_t *tbs)
{
    /* FIXME Only valid for X509v3 TBS */
    return tbs->value.list.elements[6];
}

uasn1_item_t *uasn1_x509_get_pubkey_value(uasn1_item_t *tbs)
{
    /* FIXME Only valid for X509v3 TBS */
    return tbs->value.list.elements[6]->value.list.elements[1];
}

uasn1_item_t *uasn1_dn_element(char *name, char *value)
{
    uasn1_item_t *set = uasn1_set_new(1);
    uasn1_item_t *sequence = uasn1_sequence_new(2);
    uasn1_item_t *val = uasn1_utf8_string_new((unsigned char *)value,
                                              strlen(value));
    uasn1_add(sequence, uasn1_get_oid_by_name(name));
    uasn1_add(sequence, val);
    uasn1_add(set, sequence);
    return set;
}

void uasn1_add_x509_extension(uasn1_item_t *list, char *extname,
                              char critical, uasn1_item_t *value)
{
    uasn1_item_t *extension = uasn1_sequence_new(3);
    uasn1_add(extension, uasn1_get_oid_by_name(extname));
    if(critical) {
        uasn1_add(extension, uasn1_boolean_new(uasn1_true));
    }
    uasn1_add(extension, uasn1_to_octet_string(value));
    uasn1_add(list, extension);
}
