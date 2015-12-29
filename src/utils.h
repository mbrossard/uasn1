#ifndef UASN1_UTILS_H
#define UASN1_UTILS_H

/*
 * Copyright © 2015 Mathias Brossard
 */

#include "config.h"
#include "uasn1.h"

#ifdef HAVE_OPENSSL
#include <openssl/bn.h>
#endif

/** @file utils.h */

#ifdef __cplusplus
extern "C" {
#endif

/** Encodes an uasn1_item_t object and write to file. */
int uasn1_write_encoded(uasn1_item_t *item, char *filename);

uasn1_item_t *uasn1_get_generalized_time();
uasn1_item_t *uasn1_get_utc_time();

#ifdef HAVE_OPENSSL
/** Converts an OpenSSL BIGNUM structure to a ASN1Element integer. */
uasn1_item_t *uasn1_bn_to_asn1(BIGNUM *bn);

/** Writes a buffer in Base64 format into file. */
int uasn1_write_base64_buffer(uasn1_buffer_t *buffer, FILE *f);

/** Reads a Base64 encoded file into buffer */
int uasn1_buffer_dumpBase64(uasn1_buffer_t *buffer, char *filename);
#endif

#ifdef __cplusplus
}
#endif
#endif
