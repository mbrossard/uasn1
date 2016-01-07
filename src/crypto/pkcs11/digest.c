#include "uasn1.h"
#include "crypto/key.h"
#include "crypto/cryptoki.h"

#include <string.h>

uasn1_item_t *uasn1_digest_pkcs11_octet_string(uasn1_key_t *crypto, uasn1_digest_t digest, void *data, size_t length)
{
    CK_MECHANISM mechanism = { 0, NULL_PTR, 0 };
    CK_SESSION_HANDLE h_session;
    CK_BYTE buf[64], *hash = NULL;
    CK_ULONG hlen;
    CK_RV rc;

    switch (digest) {
        case UASN1_SHA1:
            mechanism.mechanism = CKM_SHA_1;
            break;
        case UASN1_SHA256:
            mechanism.mechanism = CKM_SHA256;
            break;
        case UASN1_SHA384:
            mechanism.mechanism = CKM_SHA384;
            break;
        case UASN1_SHA512:
            mechanism.mechanism = CKM_SHA512;
            break;
    }

    rc = crypto->pkcs11.functions->C_OpenSession(crypto->pkcs11.slot, CKF_SERIAL_SESSION,
                                                 NULL_PTR, NULL_PTR, &h_session);
    if (rc != CKR_OK) {
        return NULL;
    }

    rc = crypto->pkcs11.functions->C_DigestInit(h_session, &mechanism);
    if (rc != CKR_OK) {
        return NULL;
    }

    rc = crypto->pkcs11.functions->C_Digest(h_session, data, length, buf, &hlen);
    if (rc != CKR_OK) {
        return NULL;
    }

    rc = crypto->pkcs11.functions->C_CloseSession(h_session);

    hash = malloc(hlen);
    memcpy(hash, buf, hlen);

    return uasn1_octet_string_new(hash, hlen);
}
