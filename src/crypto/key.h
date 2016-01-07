#ifndef UASN1_KEY_H
#define UASN1_KEY_H

/*
 * Copyright © 2015 Mathias Brossard
 */

#include "uasn1.h"
#include "crypto.h"
#include "cryptoki.h"

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

typedef struct {
    CK_FUNCTION_LIST_PTR functions;
    CK_SLOT_ID slot;
	CK_OBJECT_HANDLE object;
    CK_SESSION_HANDLE session;
    CK_ULONG size;
    CK_KEY_TYPE type;
    CK_OBJECT_CLASS class;
} pkcs11_key_t;

struct _uasn1_key_t {
	uasn1_crypto_provider_t provider;
	union {
		pkcs11_key_t pkcs11;
#ifdef HAVE_OPENSSL
		EVP_PKEY *openssl;
#endif
	};
};

struct _uasn1_crypto_t  {
	uasn1_crypto_provider_t provider;
	union {
        struct {
            CK_FUNCTION_LIST_PTR functions;
            CK_SLOT_ID slot;
        } pkcs11;
    };
};

uasn1_crypto_t *uasn1_pkcs11_crypto(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slot);

uasn1_item_t *uasn1_asn1_rsa_public_key(uasn1_item_t *n, uasn1_item_t *e);
uasn1_item_t *uasn1_asn1_ec_public_key(uasn1_item_t *params, uasn1_item_t *point);

#endif
