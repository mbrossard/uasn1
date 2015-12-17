#include <stdlib.h>
#include "oids.h"


unsigned char oids[] =
{
  0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01,
  /* userID [0] = 0, 9, 2342, 19200300, 100, 1, 1 -- Some oddball X.500 attribute collection */
  0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19,
  /* domainComponent [10] = 0, 9, 2342, 19200300, 100, 1, 25 -- Men are from Mars, this OID is from Pluto */
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  /* ecPublicKey [20] = 1, 2, 840, 10045, 2, 1 -- ANSI X9.62 public key type */
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01, 0x07,
  /* prime256v1 [27] = 1, 2, 840, 10045, 3, 1, 1, 7 -- ANSI X9.62 named elliptic curve */
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01,
  /* ecdsaWithSHA1 [36] = 1, 2, 840, 10045, 4, 1 -- ANSI X9.62 ECDSA algorithm with SHA1 */
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x02,
  /* ecdsaWithRecommended [43] = 1, 2, 840, 10045, 4, 2 -- ANSI X9.62 ECDSA algorithm with Recommended */
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
  /* ecdsaWithSpecified [50] = 1, 2, 840, 10045, 4, 3 -- ANSI X9.62 ECDSA algorithm with Specified */
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
  /* ecdsaWithSHA256 [57] = 1, 2, 840, 10045, 4, 3, 2 -- ANSI X9.62 ECDSA algorithm with SHA256 */
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
  /* ecdsaWithSHA384 [65] = 1, 2, 840, 10045, 4, 3, 3 -- ANSI X9.62 ECDSA algorithm with SHA384 */
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04,
  /* ecdsaWithSHA512 [73] = 1, 2, 840, 10045, 4, 3, 4 -- ANSI X9.62 ECDSA algorithm with SHA512 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  /* rsaEncryption [81] = 1, 2, 840, 113549, 1, 1, 1 -- PKCS #1 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
  /* sha1withRSAEncryption [90] = 1, 2, 840, 113549, 1, 1, 5 -- PKCS #1 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
  /* sha256WithRSAEncryption [99] = 1, 2, 840, 113549, 1, 1, 11 -- PKCS #1 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
  /* sha384WithRSAEncryption [108] = 1, 2, 840, 113549, 1, 1, 12 -- PKCS #1 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
  /* sha512WithRSAEncryption [117] = 1, 2, 840, 113549, 1, 1, 13 -- PKCS #1 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
  /* data [126] = 1, 2, 840, 113549, 1, 7, 1 -- PKCS #7 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
  /* signedData [135] = 1, 2, 840, 113549, 1, 7, 2 -- PKCS #7 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03,
  /* envelopedData [144] = 1, 2, 840, 113549, 1, 7, 3 -- PKCS #7 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x04,
  /* signedAndEnvelopedData [153] = 1, 2, 840, 113549, 1, 7, 4 -- PKCS #7 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x05,
  /* digestedData [162] = 1, 2, 840, 113549, 1, 7, 5 -- PKCS #7 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06,
  /* encryptedData [171] = 1, 2, 840, 113549, 1, 7, 6 -- PKCS #7 */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01,
  /* emailAddress [180] = 1, 2, 840, 113549, 1, 9, 1 -- PKCS #9. Deprecated, use an altName extension instead */
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x07,
  /* challengePassword [189] = 1, 2, 840, 113549, 1, 9, 7 -- PKCS #9 */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01,
  /* authorityInfoAccess [198] = 1, 3, 6, 1, 5, 5, 7, 1, 1 -- PKIX private extension */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02,
  /* policyQualifierIds [206] = 1, 3, 6, 1, 5, 5, 7, 2 -- PKIX */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01,
  /* cps [213] = 1, 3, 6, 1, 5, 5, 7, 2, 1 -- PKIX policy qualifier */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02,
  /* unotice [221] = 1, 3, 6, 1, 5, 5, 7, 2, 2 -- PKIX policy qualifier */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x03,
  /* textNotice [229] = 1, 3, 6, 1, 5, 5, 7, 2, 3 -- PKIX policy qualifier */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
  /* serverAuth [237] = 1, 3, 6, 1, 5, 5, 7, 3, 1 -- PKIX key purpose */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
  /* clientAuth [245] = 1, 3, 6, 1, 5, 5, 7, 3, 2 -- PKIX key purpose */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03,
  /* codeSigning [253] = 1, 3, 6, 1, 5, 5, 7, 3, 3 -- PKIX key purpose */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04,
  /* emailProtection [261] = 1, 3, 6, 1, 5, 5, 7, 3, 4 -- PKIX key purpose */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08,
  /* timeStamping [269] = 1, 3, 6, 1, 5, 5, 7, 3, 8 -- PKIX key purpose */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09,
  /* ocspSigning [277] = 1, 3, 6, 1, 5, 5, 7, 3, 9 -- PKIX key purpose */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09,
  /* personalData [285] = 1, 3, 6, 1, 5, 5, 7, 9 -- PKIX qualified certificates */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x01,
  /* dateOfBirth [292] = 1, 3, 6, 1, 5, 5, 7, 9, 1 -- PKIX personal data */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x02,
  /* placeOfBirth [300] = 1, 3, 6, 1, 5, 5, 7, 9, 2 -- PKIX personal data */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x03,
  /* gender [308] = 1, 3, 6, 1, 5, 5, 7, 9, 3 -- PKIX personal data */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x04,
  /* countryOfCitizenship [316] = 1, 3, 6, 1, 5, 5, 7, 9, 4 -- PKIX personal data */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x09, 0x05,
  /* countryOfResidence [324] = 1, 3, 6, 1, 5, 5, 7, 9, 5 -- PKIX personal data */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0b, 0x01,
  /* pkixQCSyntax-v1 [332] = 1, 3, 6, 1, 5, 5, 7, 11, 1 -- PKIX qualified certificates */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
  /* ocspBasic [340] = 1, 3, 6, 1, 5, 5, 7, 48, 1, 1 -- OCSP */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02,
  /* ocspNonce [349] = 1, 3, 6, 1, 5, 5, 7, 48, 1, 2 -- OCSP */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x04,
  /* ocspResponse [358] = 1, 3, 6, 1, 5, 5, 7, 48, 1, 4 -- OCSP */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x07,
  /* ocspServiceLocator [367] = 1, 3, 6, 1, 5, 5, 7, 48, 1, 7 -- OCSP */
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02,
  /* caIssuers [376] = 1, 3, 6, 1, 5, 5, 7, 48, 2 -- PKIX subject/authority info access descriptor */
  0x55, 0x04, 0x03,
  /* commonName [384] = 2, 5, 4, 3 -- X.520 DN component */
  0x55, 0x04, 0x04,
  /* surname [387] = 2, 5, 4, 4 -- X.520 DN component */
  0x55, 0x04, 0x05,
  /* serialNumber [390] = 2, 5, 4, 5 -- X.520 DN component */
  0x55, 0x04, 0x06,
  /* countryName [393] = 2, 5, 4, 6 -- X.520 DN component */
  0x55, 0x04, 0x07,
  /* localityName [396] = 2, 5, 4, 7 -- X.520 DN component */
  0x55, 0x04, 0x08,
  /* stateOrProvinceName [399] = 2, 5, 4, 8 -- X.520 DN component */
  0x55, 0x04, 0x09,
  /* streetAddress [402] = 2, 5, 4, 9 -- X.520 DN component */
  0x55, 0x04, 0x0a,
  /* organizationName [405] = 2, 5, 4, 10 -- X.520 DN component */
  0x55, 0x04, 0x0b,
  /* organizationalUnitName [408] = 2, 5, 4, 11 -- X.520 DN component */
  0x55, 0x04, 0x0c,
  /* title [411] = 2, 5, 4, 12 -- X.520 DN component */
  0x55, 0x04, 0x29,
  /* name [414] = 2, 5, 4, 41 -- X.520 DN component */
  0x55, 0x04, 0x2a,
  /* givenName [417] = 2, 5, 4, 42 -- X.520 DN component */
  0x55, 0x04, 0x2b,
  /* initials [420] = 2, 5, 4, 43 -- X.520 DN component */
  0x55, 0x04, 0x2c,
  /* generationQualifier [423] = 2, 5, 4, 44 -- X.520 DN component */
  0x55, 0x04, 0x2d,
  /* uniqueIdentifier [426] = 2, 5, 4, 45 -- X.520 DN component */
  0x55, 0x04, 0x2e,
  /* dnQualifier [429] = 2, 5, 4, 46 -- X.520 DN component */
  0x55, 0x04, 0x32,
  /* uniqueMember [432] = 2, 5, 4, 50 -- X.520 DN component */
  0x55, 0x04, 0x41,
  /* pseudonym [435] = 2, 5, 4, 65 -- X.520 DN component */
  0x55, 0x04, 0x48,
  /* role [438] = 2, 5, 4, 72 -- X.520 DN component */
  0x55, 0x1d, 0x09,
  /* subjectDirectoryAttributes [441] = 2, 5, 29, 9 -- X.509 extension */
  0x55, 0x1d, 0x0e,
  /* subjectKeyIdentifier [444] = 2, 5, 29, 14 -- X.509 extension */
  0x55, 0x1d, 0x0f,
  /* keyUsage [447] = 2, 5, 29, 15 -- X.509 extension */
  0x55, 0x1d, 0x10,
  /* privateKeyUsagePeriod [450] = 2, 5, 29, 16 -- X.509 extension */
  0x55, 0x1d, 0x11,
  /* subjectAltName [453] = 2, 5, 29, 17 -- X.509 extension */
  0x55, 0x1d, 0x13,
  /* basicConstraints [456] = 2, 5, 29, 19 -- X.509 extension */
  0x55, 0x1d, 0x14,
  /* cRLNumber [459] = 2, 5, 29, 20 -- X.509 extension */
  0x55, 0x1d, 0x15,
  /* cRLReason [462] = 2, 5, 29, 21 -- X.509 extension */
  0x55, 0x1d, 0x18,
  /* invalidityDate [465] = 2, 5, 29, 24 -- X.509 extension */
  0x55, 0x1d, 0x1f,
  /* cRLDistributionPoints [468] = 2, 5, 29, 31 -- X.509 extension */
  0x55, 0x1d, 0x20,
  /* certificatePolicies [471] = 2, 5, 29, 32 -- X.509 extension */
  0x55, 0x1d, 0x23,
  /* authorityKeyIdentifier [474] = 2, 5, 29, 35 -- X.509 extension */
  0x55, 0x1d, 0x25,
  /* extKeyUsage [477] = 2, 5, 29, 37 -- X.509 extension */
  0x55, 0x1d, 0x25, 0x00,
  /* anyExtendedKeyUsage [480] = 2, 5, 29, 37, 0 -- X.509 extended key usage */
  0x55, 0x1d, 0x26,
  /* authorityAttributeIdentifier [484] = 2, 5, 29, 38 -- X.509 extension */
  0x55, 0x1d, 0x2e,
  /* freshestCRL [487] = 2, 5, 29, 46 -- X.509 extension */
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
  /* sha-256 [490] = 2, 16, 840, 1, 101, 3, 4, 2, 1 -- NIST Algorithm */
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
  /* sha-384 [499] = 2, 16, 840, 1, 101, 3, 4, 2, 2 -- NIST Algorithm */
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
  /* sha-512 [508] = 2, 16, 840, 1, 101, 3, 4, 2, 3 -- NIST Algorithm */
  0
};

oidelement oidtable[] = 
{
  { "userID", 10, oids + 0 },
  { "domainComponent", 10, oids + 10 },
  { "ecPublicKey", 7, oids + 20 },
  { "prime256v1", 9, oids + 27 },
  { "ecdsaWithSHA1", 7, oids + 36 },
  { "ecdsaWithRecommended", 7, oids + 43 },
  { "ecdsaWithSpecified", 7, oids + 50 },
  { "ecdsaWithSHA256", 8, oids + 57 },
  { "ecdsaWithSHA384", 8, oids + 65 },
  { "ecdsaWithSHA512", 8, oids + 73 },
  { "rsaEncryption", 9, oids + 81 },
  { "sha1withRSAEncryption", 9, oids + 90 },
  { "sha256WithRSAEncryption", 9, oids + 99 },
  { "sha384WithRSAEncryption", 9, oids + 108 },
  { "sha512WithRSAEncryption", 9, oids + 117 },
  { "data", 9, oids + 126 },
  { "signedData", 9, oids + 135 },
  { "envelopedData", 9, oids + 144 },
  { "signedAndEnvelopedData", 9, oids + 153 },
  { "digestedData", 9, oids + 162 },
  { "encryptedData", 9, oids + 171 },
  { "emailAddress", 9, oids + 180 },
  { "challengePassword", 9, oids + 189 },
  { "authorityInfoAccess", 8, oids + 198 },
  { "policyQualifierIds", 7, oids + 206 },
  { "cps", 8, oids + 213 },
  { "unotice", 8, oids + 221 },
  { "textNotice", 8, oids + 229 },
  { "serverAuth", 8, oids + 237 },
  { "clientAuth", 8, oids + 245 },
  { "codeSigning", 8, oids + 253 },
  { "emailProtection", 8, oids + 261 },
  { "timeStamping", 8, oids + 269 },
  { "ocspSigning", 8, oids + 277 },
  { "personalData", 7, oids + 285 },
  { "dateOfBirth", 8, oids + 292 },
  { "placeOfBirth", 8, oids + 300 },
  { "gender", 8, oids + 308 },
  { "countryOfCitizenship", 8, oids + 316 },
  { "countryOfResidence", 8, oids + 324 },
  { "pkixQCSyntax-v1", 8, oids + 332 },
  { "ocspBasic", 9, oids + 340 },
  { "ocspNonce", 9, oids + 349 },
  { "ocspResponse", 9, oids + 358 },
  { "ocspServiceLocator", 9, oids + 367 },
  { "caIssuers", 8, oids + 376 },
  { "commonName", 3, oids + 384 },
  { "surname", 3, oids + 387 },
  { "serialNumber", 3, oids + 390 },
  { "countryName", 3, oids + 393 },
  { "localityName", 3, oids + 396 },
  { "stateOrProvinceName", 3, oids + 399 },
  { "streetAddress", 3, oids + 402 },
  { "organizationName", 3, oids + 405 },
  { "organizationalUnitName", 3, oids + 408 },
  { "title", 3, oids + 411 },
  { "name", 3, oids + 414 },
  { "givenName", 3, oids + 417 },
  { "initials", 3, oids + 420 },
  { "generationQualifier", 3, oids + 423 },
  { "uniqueIdentifier", 3, oids + 426 },
  { "dnQualifier", 3, oids + 429 },
  { "uniqueMember", 3, oids + 432 },
  { "pseudonym", 3, oids + 435 },
  { "role", 3, oids + 438 },
  { "subjectDirectoryAttributes", 3, oids + 441 },
  { "subjectKeyIdentifier", 3, oids + 444 },
  { "keyUsage", 3, oids + 447 },
  { "privateKeyUsagePeriod", 3, oids + 450 },
  { "subjectAltName", 3, oids + 453 },
  { "basicConstraints", 3, oids + 456 },
  { "cRLNumber", 3, oids + 459 },
  { "cRLReason", 3, oids + 462 },
  { "invalidityDate", 3, oids + 465 },
  { "cRLDistributionPoints", 3, oids + 468 },
  { "certificatePolicies", 3, oids + 471 },
  { "authorityKeyIdentifier", 3, oids + 474 },
  { "extKeyUsage", 3, oids + 477 },
  { "anyExtendedKeyUsage", 4, oids + 480 },
  { "authorityAttributeIdentifier", 3, oids + 484 },
  { "freshestCRL", 3, oids + 487 },
  { "sha-256", 9, oids + 490 },
  { "sha-384", 9, oids + 499 },
  { "sha-512", 9, oids + 508 },
  { NULL, 0, NULL }
};
