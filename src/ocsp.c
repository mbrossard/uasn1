/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "uasn1.h"
#include "x509.h"
#include "ocsp.h"
#include "oids.h"
#include "crypto.h"

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

uasn1_item_t *uasn1_ocsp_single_request(uasn1_crypto_t *crypto,
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
        uasn1_add(certid, uasn1_hash_to_octet_string(crypto, UASN1_SHA1, issuer_name));
        uasn1_add(certid, uasn1_hash_to_octet_string(crypto, UASN1_SHA1, public_key));
        uasn1_add(certid, uasn1_x509_get_serial(cert_tbs));

        uasn1_add(request, certid);
        uasn1_add_tagged(request, extensions, uasn1_context_specific_tag,
                         0, uasn1_explicit_tag);
        return request;
	}
    return NULL;
}

uasn1_item_t *uasn1_ocsp_get_request_list(uasn1_item_t *tbsRequest)
{
    uasn1_item_t *rv;
    unsigned int i;
    if(tbsRequest->tag.type == uasn1_sequence_type) {
        for(i = 0; i < uasn1_count(tbsRequest); i++) {
            rv = uasn1_get(tbsRequest, i);
            if(rv->tag.value == 0) {
                return rv;
            }
		}
	}
    return NULL;
}

uasn1_item_t *uasn1_ocsp_get_request_cert_id(uasn1_item_t *request)
{
    return request->value.list.elements[0];
}

uasn1_item_t *uasn1_ocsp_response(OCSPResponseStatus status,
                                  uasn1_item_t *response)

{
    uasn1_item_t *ocsp_response = uasn1_sequence_new(2);
    uasn1_item_t *response_bytes = uasn1_sequence_new(2);

    uasn1_add(response_bytes, uasn1_get_oid_by_name("ocspBasic"));
    uasn1_add(response_bytes, uasn1_to_octet_string(response));

    uasn1_add(ocsp_response, uasn1_enumerated_new(status));
    uasn1_add_tagged(ocsp_response, response_bytes, uasn1_context_specific_tag,
                     0, uasn1_explicit_tag);
    return ocsp_response;
}

uasn1_item_t *uasn1_ocsp_basic_response(uasn1_item_t *response,
                                        uasn1_key_t *key,
                                        uasn1_digest_t digest,
                                        uasn1_item_t *certificates)
{
    uasn1_item_t *basic_response = uasn1_sequence_new(4);
    uasn1_item_t *sig = NULL;
    uasn1_buffer_t *buffer = uasn1_buffer_new(128);
    uasn1_item_t *algoid;

    uasn1_encode(response, buffer);
    sig = uasn1_key_x509_sign(key, digest, buffer);
    algoid = uasn1_x509_algorithm(key, digest);

    uasn1_add(basic_response, uasn1_preencoded(buffer));
    uasn1_add(basic_response, algoid);
    uasn1_add(basic_response, sig);

    uasn1_add_tagged(basic_response, certificates, uasn1_context_specific_tag,
                      0, uasn1_explicit_tag);
    return basic_response;
}

uasn1_item_t *uasn1_ocsp_response_data(int version, uasn1_item_t *id,
                                       uasn1_item_t *time,
                                       uasn1_item_t *responses,
                                       uasn1_item_t *extensions)
{
    uasn1_item_t *response = uasn1_sequence_new(5);
    if(version != 0) {
        uasn1_add(response, uasn1_set_tag(uasn1_integer_new(version),
                                          uasn1_context_specific_tag, 0, uasn1_explicit_tag));
	}
    uasn1_add(response, id);
    uasn1_add(response, time);
    uasn1_add(response, responses);
    uasn1_add_tagged(response, extensions, uasn1_context_specific_tag,
                     0, uasn1_explicit_tag);

    return response;
}

uasn1_item_t *uasn1_ocsp_responder_id_name(uasn1_item_t *certificate)
{
    uasn1_item_t *cert_tbs = uasn1_x509_get_tbs(certificate);
    /* Oups might cause some confusion */
    return uasn1_set_tag(uasn1_x509_get_subject(cert_tbs),
                         uasn1_context_specific_tag, 1, uasn1_explicit_tag);
}

uasn1_item_t *uasn1_ocsp_responder_id_key(uasn1_crypto_t *crypto, uasn1_item_t *certificate)
{
    uasn1_item_t *cert_tbs = uasn1_x509_get_tbs(certificate);
    uasn1_item_t *public_key = uasn1_x509_get_pubkey_value(cert_tbs);
    
    return uasn1_set_tag(uasn1_hash_to_octet_string(crypto, UASN1_SHA1, public_key),
                         uasn1_context_specific_tag, 2, uasn1_explicit_tag);
}

uasn1_item_t *uasn1_ocsp_single_response(uasn1_item_t *certid,
                                         CertStatus status,
                                         uasn1_item_t *info,
                                         uasn1_item_t *thisUpdate,
                                         uasn1_item_t *nextUpdate,
                                         uasn1_item_t *extensions)
{
    uasn1_item_t *SingleResponse = uasn1_sequence_new(5);
    uasn1_add(SingleResponse, certid);
    uasn1_add(SingleResponse,
              uasn1_set_tag(((status == revoked) ? info : uasn1_item_new(uasn1_null_type)),
                            uasn1_context_specific_tag, status, uasn1_implicit_tag));
    uasn1_add(SingleResponse, thisUpdate);
    uasn1_add_tagged(SingleResponse, nextUpdate, uasn1_context_specific_tag,
                     0, uasn1_explicit_tag);
    uasn1_add_tagged(SingleResponse, extensions, uasn1_context_specific_tag,
                     1, uasn1_explicit_tag);
    return SingleResponse;
}

uasn1_item_t *uasn1_ocsp_revoked_info(uasn1_item_t *time, uasn1_item_t *reason)
{
    uasn1_item_t *info = uasn1_sequence_new(2);
    uasn1_add(info, time);
    uasn1_add_tagged(info, reason, uasn1_context_specific_tag,
                     0, uasn1_explicit_tag);
    return info;
}
