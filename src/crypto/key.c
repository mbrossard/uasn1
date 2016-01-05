
#include "config.h"
#include "uasn1.h"
#include "crypto/key.h"
#include "crypto/cryptoki.h"
#include "crypto/pkcs11/key.h"

#ifdef HAVE_OPENSSL
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#endif

#include <string.h>

uasn1_item_t *uasn1_asn1_rsa_public_key(uasn1_item_t *n, uasn1_item_t *e)
{
    uasn1_item_t *key = uasn1_sequence_new(2);
    uasn1_buffer_t *buf = uasn1_buffer_new(64);
    uasn1_item_t *k = NULL;
    uasn1_add(key, n);
    uasn1_add(key, e);
    uasn1_encode(key, buf);
    k = uasn1_bit_string_new(buf->buffer, buf->current, 0);
    uasn1_free(key);
    uasn1_buffer_free(buf);

    return k;
}

uasn1_item_t *uasn1_asn1_ec_public_key(uasn1_item_t *params, uasn1_item_t *point)
{
    unsigned int ecPublicKey[] = { 1, 2, 840, 10045, 2, 1 };
    uasn1_item_t *info = uasn1_sequence_new(2);
    uasn1_item_t *k = uasn1_sequence_new(2);

    uasn1_add(info, uasn1_oid_new(ecPublicKey, 6));
    uasn1_add(info, params);
    uasn1_add(k, info);
    uasn1_add(k, point);

    return k;
}

uasn1_item_t *uasn1_key_get_asn1_public_key(uasn1_key_t *key)
{
    uasn1_item_t *k = NULL;


    if(key->provider == UASN1_PKCS11) {
        k = uasn1_key_pkcs11_get_asn1_public_key(key);
    }

    return k;
}

uasn1_item_t *uasn1_key_get_asn1_public_key_info(uasn1_key_t *key)
{
    uasn1_item_t *key_info = NULL;

    if(key->provider == UASN1_PKCS11) {
        uasn1_item_t *public = uasn1_key_get_asn1_public_key(key);

        if (key->pkcs11.type == CKK_RSA) {
            key_info = uasn1_sequence_new(2);
            uasn1_item_t *info = uasn1_sequence_new(2);
            unsigned int rsaEncryption[] = { 1, 2, 840, 113549, 1, 1, 1 };
            uasn1_add(info, uasn1_oid_new(rsaEncryption, 7));
            uasn1_add(info, uasn1_item_new(uasn1_null_type));
            uasn1_add(key_info, info);
            uasn1_add(key_info, public);
        } else if (key->pkcs11.type == CKK_EC) {
            key_info = public;
        }
    }

    return key_info;
}

uasn1_item_t *uasn1_key_get_key_identifier(uasn1_key_t *key)
{
    uasn1_buffer_t *buf = uasn1_buffer_new(4096);
    uasn1_item_t *public = uasn1_key_get_asn1_public_key(key);
    uasn1_item_t *ki = NULL;

    uasn1_encode(public, buf);

    if(key->provider == UASN1_PKCS11) {
        CK_BYTE hash[20];
        CK_MECHANISM mechanism = { CKM_SHA_1, NULL_PTR, 0 };
        CK_ULONG len;
        CK_RV rc;

        rc = key->pkcs11.functions->C_DigestInit(key->pkcs11.session, &mechanism);
        if (rc != CKR_OK) {
            goto end;
        }
        rc = key->pkcs11.functions->C_Digest(key->pkcs11.session, buf->buffer, buf->current, hash, &len);
        if (rc != CKR_OK) {
            goto end;
        }
        ki = uasn1_octet_string_new(hash, sizeof(hash));
    }

 end:
    uasn1_buffer_free(buf);
    uasn1_free(public);

    return ki;
}

static unsigned int id_sha1[6] = { 1, 3, 14, 3, 2, 26 };
static unsigned int id_sha256[9] = { 2, 16, 840, 1, 101, 3, 4, 2, 1 };
static unsigned int id_sha384[9] = { 2, 16, 840, 1, 101, 3, 4, 2, 2 };
static unsigned int id_sha512[9] = { 2, 16, 840, 1, 101, 3, 4, 2, 3 };

uasn1_item_t *uasn1_digest_octet_string(CK_FUNCTION_LIST_PTR funcs, CK_SLOT_ID slot,
                                        uasn1_digest_t digest, CK_BYTE_PTR data, CK_ULONG length)
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

    rc = funcs->C_OpenSession(slot, CKF_SERIAL_SESSION,
                              NULL_PTR, NULL_PTR, &h_session);
    if (rc != CKR_OK) {
        return NULL;
    }

    rc = funcs->C_DigestInit(h_session, &mechanism);
    if (rc != CKR_OK) {
        return NULL;
    }

    rc = funcs->C_Digest(h_session, data, length, buf, &hlen);
    if (rc != CKR_OK) {
        return NULL;
    }

    rc = funcs->C_CloseSession(h_session);

    hash = malloc(hlen);
    memcpy(hash, buf, hlen);

    return uasn1_octet_string_new(hash, hlen);
}

uasn1_item_t *uasn1_hash_buffer_to_octet_string(uasn1_key_t *key, uasn1_digest_t digest, uasn1_buffer_t *buffer)
{
    return uasn1_digest_octet_string(key->pkcs11.functions, key->pkcs11.slot, digest, buffer->buffer, buffer->current);
}

uasn1_item_t *uasn1_hash_to_octet_string(uasn1_key_t *key, uasn1_digest_t digest, uasn1_item_t *item)
{
    uasn1_item_t *hash = NULL;
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);
    uasn1_encode(item, buffer);
    hash = uasn1_digest_octet_string(key->pkcs11.functions, key->pkcs11.slot, digest, buffer->buffer, buffer->current);
    uasn1_buffer_free(buffer);
    return hash;
}

uasn1_item_t *uasn1_digest_oid(uasn1_digest_t digest)
{
    switch (digest) {
        case UASN1_SHA1:
            return uasn1_oid_new(id_sha1, 6);
            break;
        case UASN1_SHA256:
            return uasn1_oid_new(id_sha256, 9);
            break;
        case UASN1_SHA384:
            return uasn1_oid_new(id_sha384, 9);
            break;
        case UASN1_SHA512:
            return uasn1_oid_new(id_sha512, 9);
            break;
    }
    return NULL;
}

uasn1_item_t *uasn1_key_x509_sign(uasn1_key_t *key, uasn1_digest_t digest, uasn1_buffer_t *buffer)
{
    uasn1_item_t *sig = NULL;

    if(key->provider == UASN1_PKCS11) {
        sig = uasn1_key_pkcs11_x509_sign(key, digest, buffer);
    }
    
    return sig;
}



uasn1_item_t *uasn1_x509_algorithm(uasn1_key_t *key, uasn1_digest_t digest)
{
    uasn1_item_t *algoid;
    uasn1_asymetric_t type = -1;
    unsigned int sha1withRSAEncryption[7] = { 1, 2, 840, 113549, 1, 1, 5 };
    unsigned int sha256withRSAEncryption[7] = { 1, 2, 840, 113549, 1, 1, 11 };
    unsigned int sha384withRSAEncryption[7] = { 1, 2, 840, 113549, 1, 1, 12 };
    unsigned int sha512withRSAEncryption[7] = { 1, 2, 840, 113549, 1, 1, 13 };
    unsigned int ecdsaWithSHA256[7] = { 1, 2, 840, 10045, 4, 3, 2 };

    if(key->provider == UASN1_PKCS11) {
        if (key->pkcs11.type == CKK_RSA) {
            type = UASN1_RSA;
        } else if (key->pkcs11.type == CKK_EC) {
            type = UASN1_ECDSA;
        }
    }

    switch(type) {
        case UASN1_RSA:
            algoid = uasn1_sequence_new(2);
            switch(digest) {
                case UASN1_SHA1:
                    uasn1_add(algoid, uasn1_oid_new(sha1withRSAEncryption, 7));
                    break;
                case UASN1_SHA256:
                    uasn1_add(algoid, uasn1_oid_new(sha256withRSAEncryption, 7));
                    break;
                case UASN1_SHA384:
                    uasn1_add(algoid, uasn1_oid_new(sha384withRSAEncryption, 7));
                    break;
                case UASN1_SHA512:
                    uasn1_add(algoid, uasn1_oid_new(sha512withRSAEncryption, 7));
                    break;
            }
            uasn1_add(algoid, uasn1_item_new(uasn1_null_type));
            break;
        case UASN1_ECDSA:
            algoid = uasn1_sequence_new(1);
            uasn1_add(algoid, uasn1_oid_new(ecdsaWithSHA256, 7));
            break;
        default:
            break;
    }

    return algoid;
}

uasn1_item_t *uasn1_x509_algorithm2(uasn1_key_t *key, uasn1_digest_t digest)
{
    uasn1_item_t *algoid;
    uasn1_asymetric_t type = -1;
    unsigned int rsaEncryption[7] = { 1, 2, 840, 113549, 1, 1, 1 };
    unsigned int ecdsaWithSHA256[7] = { 1, 2, 840, 10045, 4, 3, 2 };

    if(key->provider == UASN1_PKCS11) {
        if (key->pkcs11.type == CKK_RSA) {
            type = UASN1_RSA;
        } else if (key->pkcs11.type == CKK_EC) {
            type = UASN1_ECDSA;
        }
    }

    switch(type) {
        case UASN1_RSA:
            algoid = uasn1_sequence_new(2);
            uasn1_add(algoid, uasn1_oid_new(rsaEncryption, 7));
            uasn1_add(algoid, uasn1_item_new(uasn1_null_type));
            break;
        case UASN1_ECDSA:
            algoid = uasn1_sequence_new(1);
            uasn1_add(algoid, uasn1_oid_new(ecdsaWithSHA256, 7));
            break;
        default:
            break;
    }

    return algoid;
}
