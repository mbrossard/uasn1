#ifndef UASN1_REQUEST_H
#define UASN1_REQUEST_H

/*
 * Copyright © 2015 Mathias Brossard
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

#endif
