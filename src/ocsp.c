/*
 * Copyright © 2015 Mathias Brossard
 */

#include "uasn1.h"
#include "x509.h"
#include "ocsp.h"
#include "oids.h"
#include "sign.h"
#include "utils.h"

uasn1_item_t *uasn1_ocsp_request(unsigned int version,
                                 uasn1_item_t *name,
                                 uasn1_item_t *list,
                                 uasn1_item_t *extensions)
{
    uasn1_item_t *tbs = uasn1_sequence_new(4);
    uasn1_item_t *wrap = uasn1_sequence_new(1);

    if(version != 0) {
        uasn1_item_t *ver = uasn1_integer_new(version);
        uasn1_set_tag(ver, uasn1_context_specific_tag, 0, uasn1_explicit_tag);
        uasn1_add(tbs, ver);
    }

    uasn1_add_tagged(tbs, name, uasn1_context_specific_tag,
                     1, uasn1_explicit_tag);
    uasn1_add(tbs, list);
    uasn1_add_tagged(tbs, extensions, uasn1_context_specific_tag,
                     2, uasn1_explicit_tag);

    uasn1_add(wrap, tbs);
    return wrap;
}

uasn1_item_t *uasn1_ocsp_single_request(uasn1_key_t *key,
                                        uasn1_buffer_t *certificate,
                                        uasn1_buffer_t *ca_certificate,
                                        uasn1_item_t *extensions)
{
    uasn1_item_t *request = uasn1_sequence_new(2);
    uasn1_item_t *certid = uasn1_sequence_new(4);
    uasn1_item_t *cert_tbs;
    uasn1_item_t *ca_cert_tbs;
    cert_tbs = uasn1_x509_get_tbs(uasn1_decode(certificate));
    ca_cert_tbs = uasn1_x509_get_tbs(uasn1_decode(ca_certificate));

    if((cert_tbs != NULL) && (ca_cert_tbs != NULL)) {
        uasn1_item_t *issuer_name = uasn1_to_octet_string(uasn1_x509_get_subject(ca_cert_tbs));
        uasn1_item_t *public_key = uasn1_x509_get_pubkey_value(ca_cert_tbs);

        uasn1_add(certid, uasn1_digest_oid(UASN1_SHA1));
        uasn1_add(certid, uasn1_hash_to_octet_string(key, UASN1_SHA1, issuer_name));
        uasn1_add(certid, uasn1_hash_to_octet_string(key, UASN1_SHA1, public_key));
        uasn1_add(certid, uasn1_x509_get_serial(cert_tbs));

        uasn1_add(request, certid);
        uasn1_add_tagged(request, extensions, uasn1_context_specific_tag,
                         0, uasn1_explicit_tag);
        return request;
	}
    return NULL;
}
