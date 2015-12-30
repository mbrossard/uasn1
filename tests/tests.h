#ifndef UASN1_TESTS__H
#define UASN1_TESTS__H

/*
 * Copyright © 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "uasn1.h"
#include "crypto.h"
#include "cryptoki.h"

int request_test(uasn1_key_t *private, uasn1_key_t *public,
                 uasn1_digest_t digest, char *name);
int x509_self_test(uasn1_key_t *private, uasn1_key_t *public,
                   uasn1_digest_t digest, char *name);
int x509_sign_test(uasn1_key_t *private, uasn1_key_t *public,
                   uasn1_digest_t digest, char *ca, char *name);

int ocsp_request_test(uasn1_key_t *key, char *name);
int ocsp_response_test(uasn1_key_t *private, uasn1_digest_t digest, char *name);

#endif
