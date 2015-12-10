#ifndef UASN1_X509_H
#define UASN1_X509_H

/*
 * Copyright © 2015 Mathias Brossard
 */

#include "uasn1.h"

uasn1_item_t *uasn1_dn_element(char *name, char *value);
uasn1_item_t *uasn1_x509_get_tbs(uasn1_item_t *certificate);
uasn1_item_t *uasn1_x509_get_serial(uasn1_item_t *tbs);
uasn1_item_t *uasn1_x509_get_issuer(uasn1_item_t *tbs);
uasn1_item_t *uasn1_x509_get_subject(uasn1_item_t *tbs);
uasn1_item_t *uasn1_x509_get_pubkey(uasn1_item_t *tbs);
uasn1_item_t *uasn1_x509_get_pubkey_value(uasn1_item_t *tbs);

/**
 *  AlgorithmIdentifier ::= SEQUENCE {
 *      algorithm  OBJECT IDENTIFIER,
 *      parameters ANY DEFINED BY algorithm OPTIONAL
 *  }
 *
 *  Name ::= CHOICE {
 *      -- only one possibility for now --
 *      rdnSequence   RDNSequence 
 *  }
 *
 *  RDNSequence ::= SEQUENCE OF  RelativeDistinguishedName
 *
 *  RelativeDistinguishedName ::= SET SIZE (1 .. MAX) OF
 *      AttributeTypeAndDistinguishedValue
 *
 *  AttributeTypeAndDistinguishedValue ::= SEQUENCE {
 *      type                  OBJECT IDENTIFIER,
 *      value                 ANY DEFINED BY type,
 *      primaryDistinguished  BOOLEAN DEFAULT TRUE,
 *      valuesWithContext     SET SIZE (1 .. MAX) OF SEQUENCE {
 *          distingAttrValue ANY, -- DEFINED BY type ,
 *          contextList      SET SIZE (1 .. MAX) OF Context
 *      } OPTIONAL
 *  }
 *
 *  Validity ::= SEQUENCE {
 *      notBefore        Time ,
 *      notAfter         Time
 *  }
 *
 *  Time ::= CHOICE {
 *      utcTime         UTCTime,
 *      generalizedTime GeneralizedTime
 *  }
 *
 *  SubjectPublicKeyInfo ::= SEQUENCE {
 *      algorithm        AlgorithmIdentifier,
 *      subjectPublicKey BIT STRING
 *  }
 *
 *  Extensions ::= SEQUENCE OF Extension
 *  Extension ::= SEQUENCE {
 *      extnId                  OBJECT IDENTIFIER,
 *      critical                BOOLEAN DEFAULT FALSE,
 *      extnValue [UNIVERSAL 4] ANY DEFINED BY extnId
 *  }
 *
 *  SEQUENCE {
 *      version         [0]  EXPLICIT Version DEFAULT v1,
 *      serialNumber         CertificateSerialNumber,
 *      signature            AlgorithmIdentifier,
 *      issuer               Name,
 *      validity             Validity,
 *      subject              Name,
 *      subjectPublicKeyInfo SubjectPublicKeyInfo,
 *      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                           -- If present, version shall be v2 or v3
 *      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                           -- If present, version shall be v2 or v3
 *      extensions      [3]  EXPLICIT Extensions OPTIONAL
 *                           -- If present, version shall be v3
 *  }
 */
uasn1_item_t *uasn1_x509_tbs_new(int version,
                                 uasn1_item_t *serial,
                                 uasn1_item_t *issuer,
                                 uasn1_item_t *notBefore,
                                 uasn1_item_t *notAfter,
                                 uasn1_item_t *subject,
                                 uasn1_item_t *publickey,
                                 uasn1_item_t *issuerUniqueID,
                                 uasn1_item_t *subjectUniqueID,
                                 uasn1_item_t *extensions);

void uasn1_add_x509_extension(uasn1_item_t *list, char *extname,
                              char critical, uasn1_item_t *value);

#endif
