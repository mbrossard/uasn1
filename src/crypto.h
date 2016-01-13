#ifndef UASN1_CRYPTO_H
#define UASN1_CRYPTO_H

/*
 * Copyright © 2015 Mathias Brossard
 */

#include "uasn1.h"
#include "crypto/cryptoki.h"

typedef enum {
    UASN1_RSA   = 0x0,
    UASN1_ECDSA = 0x1
} uasn1_asymetric_t;

typedef enum {
    UASN1_SHA1   = 0x0,
    UASN1_SHA256 = 0x1,
    UASN1_SHA384 = 0x2,
    UASN1_SHA512 = 0x3
} uasn1_digest_t;

typedef enum {
    UASN1_PKCS11  = 0x0,
    UASN1_OPENSSL = 0x1
} uasn1_crypto_provider_t;

typedef enum {
    UASN1_PUBLIC  = 0x0,
    UASN1_PRIVATE = 0x1
} uasn1_key_type_t;

/* Opaque type for keys */
typedef struct _uasn1_key_t uasn1_key_t;

/* Opaque type for cryptographic context */
typedef struct _uasn1_crypto_t uasn1_crypto_t;

uasn1_key_t *uasn1_key_load(uasn1_crypto_t *crypto, uasn1_key_type_t type, char *label);

/* Public */

uasn1_item_t *uasn1_key_get_asn1_public_key(uasn1_key_t *key);


uasn1_key_t *uasn1_key_get_public_key(uasn1_key_t *key);

uasn1_item_t *uasn1_key_get_asn1_public_key_info(uasn1_key_t *key);

uasn1_item_t *uasn1_key_get_key_identifier(uasn1_key_t *key);


/* Digest */
uasn1_item_t *uasn1_digest_octet_string(uasn1_crypto_t *crypto, uasn1_digest_t digest,
                                        void *data, size_t length);
uasn1_item_t *uasn1_hash_buffer_to_octet_string(uasn1_crypto_t *crypto, uasn1_digest_t digest, uasn1_buffer_t *buffer);
uasn1_item_t *uasn1_hash_to_octet_string(uasn1_crypto_t *crypto, uasn1_digest_t digest, uasn1_item_t *item);

uasn1_item_t *uasn1_digest_oid(uasn1_digest_t digest);


uasn1_item_t *uasn1_x509_algorithm(uasn1_key_t *key, uasn1_digest_t digest);
uasn1_item_t *uasn1_x509_algorithm2(uasn1_key_t *key, uasn1_digest_t digest);

uasn1_item_t *uasn1_key_sign(uasn1_key_t *key, unsigned char *data,
                             size_t size, uasn1_type_t encoding);

uasn1_item_t *uasn1_key_x509_sign(uasn1_key_t *key, uasn1_digest_t digest, uasn1_buffer_t *buffer);

int uasn1_x509_sign(uasn1_item_t *tbs,
                    uasn1_key_t *key,
                    uasn1_digest_t digest,
                    uasn1_buffer_t *buffer);

#endif
