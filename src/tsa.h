#ifndef UASN1_TSA_H
#define UASN1_TSA_H

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
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

/**
 *  TSTInfo ::= SEQUENCE {
 *       version          INTEGER  { v1(1) },
 *       policy           TSAPolicyId,
 *       messageImprint   MessageImprint,
 *                        -- MUST have the same value as the similar
 *                        -- field in TimeStampReq
 *       serialNumber     INTEGER,
 *                        -- Time-Stamping users MUST be ready to
 *                        -- accommodate integers up to 160 bits.
 *       genTime          GeneralizedTime,
 *       accuracy         Accuracy            OPTIONAL,
 *       ordering         BOOLEAN             DEFAULT FALSE,
 *       nonce            INTEGER             OPTIONAL,
 *                        -- MUST be present if the similar field was
 *                        -- present in TimeStampReq.  In that case it
 *                        -- MUST have the same value.
 *       tsa          [0] GeneralName         OPTIONAL,
 *       extensions   [1] IMPLICIT Extensions OPTIONAL
 *  }
 */

uasn1_item_t *uasn1_tstinfo(uasn1_item_t *policy,
                            uasn1_item_t *imprint,
                            uasn1_item_t *serial,
                            uasn1_item_t *time,
                            uasn1_item_t *accuracy,
                            uasn1_item_t *ordering,
                            uasn1_item_t *nonce,
                            uasn1_item_t *tsa,
                            uasn1_item_t *extensions);

/**
 *  SignedData ::= SEQUENCE {
 *      version              CMSVersion,
 *      digestAlgorithms     DigestAlgorithmIdentifiers,
 *      encapContentInfo     EncapsulatedContentInfo,
 *      certificates     [0] IMPLICIT CertificateSet OPTIONAL,
 *      crls             [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *      signerInfos          SignerInfos
 *  }
 *
 *  DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 *
 *  EncapsulatedContentInfo ::= SEQUENCE {
 *      eContentType     ContentType,
 *      eContent     [0] EXPLICIT OCTET STRING OPTIONAL
 *  }
 *
 *  SignerInfos ::= SET OF SignerInfo
 *
 *  SignerInfo ::= SEQUENCE {
 *      version                CMSVersion,
 *      sid                    SignerIdentifier,
 *      digestAlgorithm        DigestAlgorithmIdentifier,
 *      signedAttrs        [0] IMPLICIT SignedAttributes OPTIONAL,
 *      signatureAlgorithm     SignatureAlgorithmIdentifier,
 *      signature              SignatureValue,
 *      unsignedAttrs      [1] IMPLICIT UnsignedAttributes OPTIONAL
 *  }
 *
 *  SignerIdentifier ::= CHOICE {
 *      issuerAndSerialNumber IssuerAndSerialNumber,
 *      subjectKeyIdentifier [0] SubjectKeyIdentifier
 *  }
 *
 *  IssuerAndSerialNumber ::= SEQUENCE {
 *      issuer Name,
 *      serialNumber CertificateSerialNumber
 *  }
 *
 *  Name ::= CHOICE {
 *      -- only one possibility for now --
 *      rdnSequence  RDNSequence
 *  }
 *
 *  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *  DistinguishedName ::= RDNSequence
 *
 *  RelativeDistinguishedName ::= SET SIZE (1 .. MAX) OF
 *      AttributeTypeAndDistinguishedValue
 *
 *  AttributeTypeAndDistinguishedValue ::= SEQUENCE {
 *      type                 OBJECT IDENTIFIER,
 *      value                ANY DEFINED BY type,
 *      primaryDistinguished BOOLEAN DEFAULT TRUE,
 *      valuesWithContext    SET SIZE (1 .. MAX) OF SEQUENCE {
 *          distingAttrValue ANY, -- DEFINED BY type ,
 *          contextList      SET SIZE (1 .. MAX) OF Context
 *      } OPTIONAL
 *  }
 */

uasn1_item_t *uasn1_tsa_response(uasn1_item_t *tstinfo,
                                 uasn1_digest_t digest,
                                 uasn1_item_t *time,
                                 uasn1_buffer_t *crt,
                                 uasn1_crypto_t *crypto,
                                 uasn1_key_t *key);

uasn1_item_t *uasn1_tsa_attribute(uasn1_item_t *oid,
                                  uasn1_item_t *content);

/**
 *  TimeStampResp ::= SEQUENCE  {
 *      status         PKIStatusInfo,
 *      timeStampToken TimeStampToken OPTIONAL
 *  }
 *
 *  PKIStatusInfo ::= SEQUENCE {
 *      status       PKIStatus,
 *      statusString PKIFreeText    OPTIONAL,
 *      failInfo     PKIFailureInfo OPTIONAL
 *  }
 *
 *  PKIStatus ::= INTEGER {
 *      granted                (0), -- when the PKIStatus contains the
 *                                  -- value zero a TimeStampToken, as
 *                                  -- requested, is present.
 *      grantedWithMods        (1), -- when the PKIStatus contains the
 *                                  -- value one a TimeStampToken, with
 *                                  -- modifications, is present.
 *      rejection              (2),
 *      waiting                (3),
 *      revocationWarning      (4), -- this message contains a warning that
 *                                  -- a revocation is imminent
 *      revocationNotification (5)  -- notification that a revocation
 *                                  -- has occurred
 *  }
 *
 *  PKIFailureInfo ::= BIT STRING {
 *      badAlg               (0),
 *      -- unrecognized or unsupported Algorithm Identifier
 *      badRequest           (2),
 *      -- transaction not permitted or supported
 *      badDataFormat        (5),
 *      -- the data submitted has the wrong format
 *      timeNotAvailable    (14),
 *      -- the TSA's time source is not available
 *      unacceptedPolicy    (15),
 *      -- the requested TSA policy is not supported by the TSA.
 *      unacceptedExtension (16),
 *      -- the requested extension is not supported by the TSA.
 *      addInfoNotAvailable (17),
 *      -- the additional information requested could not be understood
 *      -- or is not available
 *      systemFailure       (25)
 *      -- the request cannot be handled due to system failure
 *  }
 *
 *  TimeStampToken ::= ContentInfo
 *
 *  ContentInfo ::= SEQUENCE {
 *      contentType     ContentType,
 *      content     [0] EXPLICIT ANY DEFINED BY contentType
 *  }
 *
 *  -- contentType is id-signedData as defined in [CMS]
 *  -- content is SignedData as defined in([CMS])
 *  -- eContentType within SignedData is id-ct-TSTInfo
 *  -- eContent within SignedData is TSTInfo
 */

#endif
