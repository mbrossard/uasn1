#ifndef UASN1_OCSP_H
#define UASN1_OCSP_H

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
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

uasn1_item_t *uasn1_ocsp_single_request(uasn1_crypto_t *crypto,
                                        uasn1_buffer_t *certificate,
                                        uasn1_buffer_t *ca_certificate,
                                        uasn1_item_t *extensions);

/**
 *
 * Request ::= SEQUENCE {
 *     reqCert                     CertID,
 *     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
 * }
 *
 *
 * CertID ::= SEQUENCE {
 *     hashAlgorithm  AlgorithmIdentifier,
 *     issuerNameHash OCTET STRING, -- Hash of Issuer's DN
 *     issuerKeyHash  OCTET STRING, -- Hash of Issuers public key
 *     serialNumber   CertificateSerialNumber
 * }
 */
uasn1_item_t *uasn1_ocsp_get_request_list(uasn1_item_t *request);
uasn1_item_t *uasn1_ocsp_get_request_cert_id(uasn1_item_t *request);

typedef enum {
    successful       = 0, /* Response has valid confirmations */
    malformedRequest = 1, /* Illegal confirmation request */
    internalError    = 2, /* Internal error in issuer */
    tryLater         = 3, /* Try again later */
    /* 4 is not used */
    sigRequired      = 5, /* Must sign the request */
    unauthorized     = 6  /* Request unauthorized */
} OCSPResponseStatus;

typedef enum {
    good    = 0,
    revoked = 1,
    unknown = 2
} CertStatus;

/**
 *
 * OCSPResponse ::= SEQUENCE {
 *     responseStatus     OCSPResponseStatus,
 *     responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL
 * }
 *
 * OCSPResponseStatus ::= ENUMERATED {
 *     successful       (0),  --Response has valid confirmations
 *     malformedRequest (1),  --Illegal confirmation request
 *     internalError    (2),  --Internal error in issuer
 *     tryLater         (3),  --Try again later
 *                            --(4) is not used
 *     sigRequired      (5),  --Must sign the request
 *     unauthorized     (6)   --Request unauthorized
 * }
 *
 * ResponseBytes ::= SEQUENCE {
 *     responseType OBJECT IDENTIFIER,
 *     response     OCTET STRING
 * }
 *
 * id-pkix-ocsp       OBJECT IDENTIFIER ::= { id-ad-ocsp }
 * id-pkix-ocsp-basic OBJECT IDENTIFIER ::= { id-pkix-ocsp 1 }
*/

uasn1_item_t *uasn1_ocsp_response(OCSPResponseStatus status,
                                  uasn1_item_t *response);

/**
 *
 * BasicOCSPResponse ::= SEQUENCE {
 *     tbsResponseData        ResponseData,
 *     signatureAlgorithm     AlgorithmIdentifier,
 *     signature              BIT STRING,
 *     certs              [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
 * }
 */

uasn1_item_t *uasn1_ocsp_basic_response(uasn1_item_t *response,
                                        uasn1_key_t *key,
                                        uasn1_digest_t digest,
                                        uasn1_item_t *certificates);

/**
 *
 * ResponseData ::= SEQUENCE {
 *         version              [0] EXPLICIT Version DEFAULT v1,
 *         responderID              ResponderID,
 *         producedAt               GeneralizedTime,
 *         responses                SEQUENCE OF SingleResponse,
 *         responseExtensions   [1] EXPLICIT Extensions OPTIONAL
 * }
 */
uasn1_item_t *uasn1_ocsp_response_data(int version, uasn1_item_t *id,
                                       uasn1_item_t *time,
                                       uasn1_item_t *responses,
                                       uasn1_item_t *extensions);

/**
 *
 * ResponderID ::= CHOICE {
 *         byName               [1] Name,
 *         byKey                [2] KeyHash
 * }
 *
 * KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
 *                          -- (excluding the tag and length fields)
 */
uasn1_item_t *uasn1_ocsp_responder_id_name(uasn1_item_t *certificate);

uasn1_item_t *uasn1_ocsp_responder_id_key(uasn1_crypto_t *crypto,
                                          uasn1_item_t *certificate);

/**
 *
 * SingleResponse ::= SEQUENCE {
 *     certID               CertID,
 *     certStatus           CertStatus,
 *     thisUpdate           GeneralizedTime,
 *     nextUpdate       [0] EXPLICIT GeneralizedTime OPTIONAL,
 *     singleExtensions [1] EXPLICIT Extensions OPTIONAL
 * }
 *
 * CertStatus ::= CHOICE {
 *     good    [0] IMPLICIT NULL,
 *     revoked [1] IMPLICIT RevokedInfo,
 *     unknown [2] IMPLICIT UnknownInfo
 * }
 */
uasn1_item_t *uasn1_ocsp_single_response(uasn1_item_t *certid,
                                         CertStatus status,
                                         uasn1_item_t *info,
                                         uasn1_item_t *thisUpdate,
                                         uasn1_item_t *nextUpdate,
                                         uasn1_item_t *extensions);

/**
 *
 * RevokedInfo ::= SEQUENCE {
 *     revocationTime       GeneralizedTime,
 *     revocationReason [0] EXPLICIT CRLReason OPTIONAL
 * }
 *
 * UnknownInfo ::= NULL -- this can be replaced with an enumeration
 *
 */
uasn1_item_t *uasn1_ocsp_revoked_info(uasn1_item_t *time, uasn1_item_t *reason);

#endif
