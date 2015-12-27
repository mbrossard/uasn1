#ifndef UASN1_OCSP_H
#define UASN1_OCSP_H

/*
 * Copyright © 2015 Mathias Brossard
 */

#include "uasn1.h"
#include "crypto.h"

/**
 * OCSPRequest ::= SEQUENCE {
 *     tbsRequest            TBSRequest,
 *     optionalSignature [0] EXPLICIT Signature OPTIONAL
 * }
 *
 * Signature ::= SEQUENCE {
 *     signatureAlgorithm     AlgorithmIdentifier,
 *     signature              BIT STRING,
 *     certs              [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
 * }
 */

/**
 *
 * TBSRequest ::= SEQUENCE {
 *     version           [0] EXPLICIT Version DEFAULT v1,
 *     requestorName     [1] EXPLICIT GeneralName OPTIONAL,
 *     requestList           SEQUENCE OF Request,
 *     requestExtensions [2] EXPLICIT Extensions OPTIONAL
 * }
 *
 * Version ::= INTEGER { v1(0) }
 */

uasn1_item_t *uasn1_ocsp_request(unsigned int version,
                                 uasn1_item_t *name,
                                 uasn1_item_t *list,
                                 uasn1_item_t *extensions);

uasn1_item_t *uasn1_ocsp_single_request(uasn1_buffer_t *certificate,
                                        uasn1_buffer_t *ca_certificate,
                                        uasn1_item_t *extensions);

#endif
