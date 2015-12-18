#ifndef UASN1_PKIX_H
#define UASN1_PKIX_H

/*
 * Copyright © 2015 Mathias Brossard
 */

#include "uasn1.h"

/**
 *  KeyUsage ::= BIT STRING {
 *      digitalSignature        (0),
 *      nonRepudiation          (1),
 *      keyEncipherment         (2),
 *      dataEncipherment        (3),
 *      keyAgreement            (4),
 *      keyCertSign             (5),
 *      cRLSign                 (6),
 *      encipherOnly            (7),
 *      decipherOnly            (8)
 *  }
 */

enum {
    digitalSignature = 0x8000,
    nonRepudiation   = 0x4000,
    keyEncipherment  = 0x2000,
    dataEncipherment = 0x1000,
    keyAgreement     = 0x800,
    keyCertSign      = 0x400,
    cRLSign          = 0x200,
    encipherOnly     = 0x100,
    decipherOnly     = 0x80
};

void uasn1_x509_add_key_usage(uasn1_item_t *extensions,
                              unsigned char critical,
                              unsigned int keyusage);

void uasn1_x509_add_ext_key_usage(uasn1_item_t *extensions,
                                  unsigned char critical,
                                  char **usages);

/**
 *  SubjectAltName ::= GeneralNames
 *
 *  GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 *  GeneralName ::= CHOICE {
 *      otherName                 [0] OtherName,
 *      rfc822Name                [1] IA5String,
 *      dNSName                   [2] IA5String,
 *      x400Address               [3] ORAddress,
 *      directoryName             [4] Name,
 *      ediPartyName              [5] EDIPartyName,
 *      uniformResourceIdentifier [6] IA5String,
 *      iPAddress                 [7] OCTET STRING,
 *      registeredID              [8] OBJECT IDENTIFIER
 *  }
 *
 *  OtherName ::= SEQUENCE {
 *      type-id     OBJECT IDENTIFIER,
 *      value   [0] EXPLICIT ANY DEFINED BY type-id
 *  }
 *
 *  EDIPartyName ::= SEQUENCE {
 *  nameAssigner [0] DirectoryString OPTIONAL,
 *  partyName    [1] DirectoryString }
 */

enum {
    otherName                  = 0x0,
    rfc822Name                 = 0x1,
    dNSName                    = 0x2,
    x400Address                = 0x3,
    directoryName              = 0x4,
    ediPartyName               = 0x5,
    uniformResourceIdentifier  = 0x6,
    iPAddress                  = 0x7,
    registeredID               = 0x8
};

void uasn1_x509_add_subject_alt_name(uasn1_item_t *extensions,
                                     unsigned char critical,
                                     unsigned int length,
                                     void **values,
                                     int *type);

void uasn1_x509_add_basic_constraints(uasn1_item_t *extensions,
                                      unsigned char critical,
                                      unsigned char ca,
                                      unsigned char pathLen,
                                      unsigned int length);
/*
void uasn1_x509_add_ski(uasn1_item_t *extensions,
                        unsigned char critical,
                        uasn1_item_t *key);

void uasn1_x509_add_aki(uasn1_item_t *extensions,
                        unsigned char critical,
                        uasn1_item_t *key);
*/

/**
 *  cRLDistributionPoints ::= { CRLDistPointsSyntax }
 *
 *  CRLDistPointsSyntax ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 *
 *  DistributionPoint ::= SEQUENCE {
 *      distributionPoint [0] DistributionPointName OPTIONAL,
 *      reasons           [1] ReasonFlags OPTIONAL,
 *      cRLIssuer         [2] GeneralNames OPTIONAL
 *  }
 *
 *  DistributionPointName ::= CHOICE {
 *      fullName                [0] GeneralNames,
 *      nameRelativeToCRLIssuer [1] RelativeDistinguishedName
 *  }
 *
 *  ReasonFlags ::= BIT STRING {
 *      unused                  (0),
 *      keyCompromise           (1),
 *      cACompromise            (2),
 *      affiliationChanged      (3),
 *      superseded              (4),
 *      cessationOfOperation    (5),
 *      certificateHold         (6)
 *   }
 */

enum {
    distributionPoint        = 0x0,
    reasons                  = 0x1,
    cRLIssuer                = 0x2
} DistributionPoint;

enum {
    fullName                  =  0x0,
    nameRelativeToCRLIssuer   =  0x1
} DistributionPointName;

enum {
    unused                =  0x80,
    keyCompromise         =  0x40,
    cACompromise          =  0x20,
    affiliationChanged    =  0x10,
    superseded            =  0x8,
    cessationOfOperation  =  0x4,
    certificateHold       =  0x2
} ReasonFlags;

typedef enum {
    dateOfBirth          = 0,
    placeOfBirth         = 1,
    gender               = 2,
    countryOfCitizenship = 3,
    countryOfResidence   = 4,
    maxSDA               = 5
} uasn1_x509_sda_types_t;

typedef struct {
    char *value;
    char type;
} uasn1_x509_sda_t;

uasn1_item_t *uasn1_x509_subject_directory_attribute(char *name, char *value,
                                                     uasn1_type_t type);
void uasn1_x509_add_subject_directory_attribute(uasn1_item_t *extensions,
                                                uasn1_x509_sda_t *elements);

#endif
