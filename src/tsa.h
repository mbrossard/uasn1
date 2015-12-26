#ifndef UASN1_TSA_H
#define UASN1_TSA_H

/*
 * Copyright © 2015 Mathias Brossard
 */

#include "uasn1.h"
#include "crypto.h"

/**
 *  TimeStampReq ::= SEQUENCE  {
 *      version            INTEGER  { v1(1) },
 *      messageImprint     MessageImprint,
 *                         -- a hash algorithm OID and the hash value
 *                         -- of the data to be time-stamped
 *      reqPolicy          TSAPolicyId         OPTIONAL,
 *      nonce              INTEGER             OPTIONAL,
 *      certReq            BOOLEAN             DEFAULT FALSE,
 *      extensions     [0] IMPLICIT Extensions OPTIONAL
 *  }
 *
 *  MessageImprint ::= SEQUENCE  {
 *      hashAlgorithm      AlgorithmIdentifier,
 *      hashedMessage      OCTET STRING 
 *  }
 *
 *  Extensions  ::= SEQUENCE OF  Extension
 *
 *  Extension  ::= SEQUENCE {
 *      extnId        OBJECT IDENTIFIER,
 *      critical      BOOLEAN DEFAULT FALSE,
 *      extnValue     [UNIVERSAL 4] ANY DEFINED BY extnId
 *   }
 */

uasn1_item_t *uasn1_tsa_imprint(uasn1_digest_t digest,
                                uasn1_item_t *hash);

uasn1_item_t *uasn1_tsa_request(uasn1_item_t *imprint,
                                uasn1_item_t *policy,
                                uasn1_item_t *nonce,
                                uasn1_item_t *certReq,
                                uasn1_item_t *extensions);

#endif
