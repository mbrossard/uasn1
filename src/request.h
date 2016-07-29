#ifndef UASN1_REQUEST_H
#define UASN1_REQUEST_H

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "uasn1.h"

/**
 *  AlgorithmIdentifier ::= SEQUENCE {
 *       algorithm          OBJECT IDENTIFIER,
 *       parameters         ANY DEFINED BY algorithm OPTIONAL
 *  }
 *
 *  SubjectPublicKeyInfo ::= SEQUENCE {
 *       algorithm        AlgorithmIdentifier,
 *       subjectPublicKey BIT STRING
 *  }
 *
 *  Attribute ::= SEQUENCE {
 *       type   OBJECT IDENTIFIER,
 *       values SET SIZE(1..MAX) OF ANY DEFINED BY type
 *  }
 *
 *  Attributes ::= SET OF Attribute
 *
 *  CertificationRequestInfo ::= SEQUENCE {
 *       version       INTEGER { v1(0) },
 *       subject       Name,
 *       subjectPKInfo SubjectPublicKeyInfo,
 *       attributes    [0] Attributes
 *  }
 *
 *  CertificationRequest ::= SEQUENCE {
 *       certificationRequestInfo CertificationRequestInfo,
 *       signatureAlgorithm AlgorithmIdentifier,
 *       signature          BIT STRING
 *  }
 */

/**
 * @function uasn1_request_tbs_new
 */
uasn1_item_t *uasn1_request_tbs_new(uasn1_item_t *subject,
                                    uasn1_item_t *public,
                                    uasn1_item_t *attributes);

/**
 * @function uasn1_request_add_attribute
 */
void uasn1_request_add_attribute(uasn1_item_t *set,
                                 uasn1_item_t *attribute);

/**
 * @function uasn1_request_sign
 */
int uasn1_request_sign(uasn1_item_t *tbs,
                       uasn1_key_t *key,
                       uasn1_digest_t digest,
                       uasn1_buffer_t *buffer);

#endif
