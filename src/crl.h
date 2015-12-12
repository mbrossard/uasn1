#ifndef UASN1_CRL_H
#define UASN1_CRL_H

/*
 * Copyright © 2015 Mathias Brossard
 */

#include "uasn1.h"
#include "sign.h"

typedef enum {
	unspecified          = 0,
	keyCompromise        = 1,
	cACompromise         = 2,
	affiliationChanged   = 3,
	superseded           = 4,
	cessationOfOperation = 5,
	certificateHold      = 6,
	removeFromCRL        = 8
} uasn1_crl_reason_t;

/**
 *  CertificateList ::= SEQUENCE {
 *      tbsCertList        TBSCertList,
 *      signatureAlgorithm AlgorithmIdentifier,
 *      signatureValue     BIT STRING
 *  }
 */

/**
 *  TBSCertList ::= SEQUENCE {
 *      version                 Version OPTIONAL,
 *      -- if present, shall be v2
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      thisUpdate              Time,
 *      nextUpdate              Time OPTIONAL,
 *      revokedCertificates SEQUENCE OF SEQUENCE  {
 *          userCertificate    CertificateSerialNumber,
 *          revocationDate     Time,
 *          crlEntryExtensions Extensions OPTIONAL -- if present, shall be v2
 *      } OPTIONAL,
 *      crlExtensions       [0] EXPLICIT Extensions OPTIONAL
 *                          -- if present, shall be v2
 *  }
 */

/**
 * @function uasn1_crl_tbs_new
 */
uasn1_item_t *uasn1_crl_tbs_new(uasn1_item_t *signature,
                                uasn1_item_t *issuer,
                                uasn1_item_t *thisUpdate,
                                uasn1_item_t *nextUpdate,
                                uasn1_item_t *revoked,
                                uasn1_item_t *extensions);

/**
 * @function uasn1_crl_add_entry
 */
void uasn1_crl_add_entry(uasn1_item_t *list, int cert,
                         char *date, uasn1_item_t *extensions);

/**
 * @function uasn1_crl_reason
 */
uasn1_item_t *uasn1_crl_reason(uasn1_crl_reason_t reason);

#endif
