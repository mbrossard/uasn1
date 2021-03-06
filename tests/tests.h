#ifndef UASN1_TESTS__H
#define UASN1_TESTS__H

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "uasn1.h"
#include "crypto.h"

int request_test(uasn1_key_t *private, uasn1_key_t *public,
                 uasn1_digest_t digest, char *name);
int x509_self_test(uasn1_key_t *private, uasn1_key_t *public,
                   uasn1_digest_t digest, char *name);
int x509_sign_test(uasn1_key_t *private, uasn1_key_t *public,
                   uasn1_digest_t digest, char *ca, char *name);
int crl_test(uasn1_key_t *key, uasn1_digest_t digest, char *name);

int ocsp_request_test(uasn1_crypto_t *crypto, char *ca, char *name);
int ocsp_response_test(uasn1_key_t *private, uasn1_digest_t digest, char *name);

int tsa_request_test(uasn1_crypto_t *crypto, uasn1_digest_t digest, char *name);
int tsa_response_test(uasn1_digest_t digest, char *name, char *crt_path,
                      uasn1_crypto_t *crypto, uasn1_key_t *key);

#endif
