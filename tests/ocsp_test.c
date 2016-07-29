/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "tests.h"
#include "ocsp.h"
#include "x509.h"
#include "utils.h"

#include <string.h>
#include <stdio.h>

int ocsp_request_test(uasn1_crypto_t *crypto, char *ca, char *name)
{
    uasn1_item_t *list = uasn1_sequence_new(1);
    uasn1_item_t *req;
    uasn1_buffer_t *crt1 = uasn1_buffer_new(64);
    uasn1_buffer_t *crt2 = uasn1_buffer_new(64);
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);
    char fname[64];

    sprintf(fname, "%s.der", name);
	uasn1_load_buffer(crt1, fname);
    sprintf(fname, "%s.der", ca);
	uasn1_load_buffer(crt2, fname);

	uasn1_add(list, uasn1_ocsp_single_request(crypto, crt1, crt2, NULL));

	req = uasn1_ocsp_request(0, NULL, list, NULL);

    uasn1_encode(req, buffer);

    sprintf(fname, "%s_req.der", name);
    uasn1_write_buffer(buffer, fname);

    uasn1_buffer_free(buffer);
    return 0;
}

int ocsp_response_test(uasn1_key_t *private, uasn1_digest_t digest, char *name)
{
    uasn1_buffer_t *buffer;
    uasn1_item_t *request, *requestlist;
    uasn1_item_t *responsedata;
    uasn1_item_t *responselist;
    uasn1_item_t *basicresponse;
    uasn1_item_t *ocsp;
    uasn1_item_t *cert, *certs, *certbin;
    unsigned int i;
    char fname[64];

    buffer = uasn1_buffer_new(64);
    sprintf(fname, "%s_req.der", name);
    uasn1_load_buffer(buffer, fname);
    request = uasn1_decode(buffer);
    uasn1_buffer_free(buffer);

    buffer = uasn1_buffer_new(64);
    sprintf(fname, "%s.der", name);
    uasn1_load_buffer(buffer, fname);
    certbin = uasn1_preencoded(buffer);
    cert = uasn1_decode(buffer);
    uasn1_buffer_free(buffer);

    requestlist = uasn1_ocsp_get_request_list(uasn1_x509_get_tbs(request));
    responselist = uasn1_sequence_new(1);

    for(i = 0; i < uasn1_count(requestlist); i++) {
        uasn1_item_t *certid = uasn1_ocsp_get_request_cert_id(uasn1_get(requestlist,i));
        uasn1_item_t *single = uasn1_ocsp_single_response
            (certid, good, NULL, uasn1_get_generalized_time(0), NULL, NULL);
        uasn1_add(responselist, single);
	}

    responsedata = uasn1_ocsp_response_data(0, uasn1_ocsp_responder_id_name(cert),
                                            uasn1_get_generalized_time(0),
                                            responselist, NULL);

    certs = uasn1_sequence_new(1);
    uasn1_add(certs, certbin);
    basicresponse = uasn1_ocsp_basic_response(responsedata, private, digest, certs);

    ocsp = uasn1_ocsp_response(successful, basicresponse);

    buffer = uasn1_buffer_new(64);
    uasn1_encode(ocsp, buffer);
    sprintf(fname, "%s_res.der", name);
    uasn1_write_buffer(buffer, fname);
    uasn1_buffer_free(buffer);

    return 0;
}
