#ifndef UASN1_CRYPTO_KEY_PKCS11_H
#define UASN1_CRYPTO_KEY_PKCS11_H

/*
 * Copyright © 2015 Mathias Brossard
 */

#include "crypto.h"

uasn1_item_t *uasn1_key_pkcs11_get_asn1_public_key(uasn1_key_t *key);

#endif
