
#include "config.h"
#include "uasn1.h"
#include "key.h"
#include "cryptoki.h"

#ifdef HAVE_OPENSSL
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#endif

#include <string.h>

uasn1_key_t *uasn1_load_pkcs11_key(CK_FUNCTION_LIST_PTR funcs, CK_SLOT_ID slot,
                                   CK_OBJECT_CLASS class, CK_BYTE_PTR label)
{
    CK_SESSION_HANDLE h_session;
    CK_OBJECT_HANDLE  h_object = -1;
    CK_ATTRIBUTE      search[2] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_LABEL, label, strlen((char *)label) }
    };
    CK_KEY_TYPE       type;
    CK_ATTRIBUTE      attrs[1] = {
        { CKA_KEY_TYPE, &type, sizeof(type) }
    };
    CK_ULONG          found;
    CK_RV             rc;
    uasn1_key_t       *key = NULL;

    rc = funcs->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &h_session);
    if (rc != CKR_OK) {
        return NULL;
    }

    rc = pkcs11_find_object(funcs, h_session, search, 2, &h_object, 1, &found);
    if ((rc != CKR_OK) || (found == 0)) {
        goto fail;
    }

    rc = funcs->C_GetAttributeValue(h_session, h_object, attrs, 1);
    if (rc != CKR_OK) {
        goto fail;
    }

    key = malloc(sizeof(uasn1_key_t));
    if(key == NULL) {
        goto fail;
    }

    key->provider = UASN1_PKCS11;
    key->pkcs11.functions = funcs;
    key->pkcs11.slot = slot;
    key->pkcs11.object = h_object;
    key->pkcs11.session = h_session;
    key->pkcs11.size = 0;
    key->pkcs11.type = type;
    key->pkcs11.class = class;

    return key;

 fail:
    funcs->C_CloseSession(h_session);
    free(key);
    return NULL;
}

static uasn1_item_t *uasn1_asn1_rsa_public_key(uasn1_item_t *n, uasn1_item_t *e)
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

static uasn1_item_t *uasn1_asn1_ec_public_key(uasn1_item_t *params, uasn1_item_t *point)
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
        CK_ATTRIBUTE attrs[2];
        CK_RV        rc;

        if (key->pkcs11.type == CKK_RSA) {
            uasn1_item_t *n, *e;

            pkcs11_fill_attribute(&attrs[0], CKA_PUBLIC_EXPONENT, NULL, 0);
            pkcs11_fill_attribute(&attrs[1], CKA_MODULUS,         NULL, 0);

            if ((rc = key->pkcs11.functions->C_GetAttributeValue
                 (key->pkcs11.session, key->pkcs11.object, attrs, 2)) != CKR_OK) {
                goto done;
            }

            if (((attrs[0].pValue = malloc(attrs[0].ulValueLen)) == NULL) ||
                ((attrs[1].pValue = malloc(attrs[1].ulValueLen)) == NULL)) {
                rc = CKR_HOST_MEMORY;
                goto done;
            }

            if ((rc = key->pkcs11.functions->C_GetAttributeValue
                 (key->pkcs11.session, key->pkcs11.object, attrs, 2)) != CKR_OK) {
                goto done;
            }

            e = uasn1_string_new(uasn1_integer_type, attrs[0].pValue, attrs[0].ulValueLen);
            n = uasn1_string_new(uasn1_integer_type, attrs[1].pValue, attrs[1].ulValueLen);
            k = uasn1_asn1_rsa_public_key(n, e);
            attrs[0].pValue = NULL;
            attrs[1].pValue = NULL;
        } else if (key->pkcs11.type == CKK_EC) {
            uasn1_item_t *params, *point;
 
            pkcs11_fill_attribute(&attrs[0], CKA_EC_PARAMS, NULL, 0);
            pkcs11_fill_attribute(&attrs[1], CKA_EC_POINT,  NULL, 0);

            if ((rc = key->pkcs11.functions->C_GetAttributeValue
                 (key->pkcs11.session, key->pkcs11.object, attrs, 2)) != CKR_OK) {
                goto done;
            }

            if (((attrs[0].pValue = malloc(attrs[0].ulValueLen)) == NULL) ||
                ((attrs[1].pValue = malloc(attrs[1].ulValueLen)) == NULL)) {
                rc = CKR_HOST_MEMORY;
                goto done;
            }

            if ((rc = key->pkcs11.functions->C_GetAttributeValue
                 (key->pkcs11.session, key->pkcs11.object, attrs, 2)) != CKR_OK) {
                goto done;
            }

            params = uasn1_string_new(uasn1_oid_type, attrs[0].pValue, attrs[0].ulValueLen);
            params->tag.flags = uasn1_preencoded_type;
            point = uasn1_bit_string_new(attrs[1].pValue + 2, attrs[1].ulValueLen - 2, 0);

            k = uasn1_asn1_ec_public_key(params, point);
            attrs[0].pValue = NULL;
            attrs[1].pValue = NULL;
        }

    done:
        free(attrs[0].pValue);
        free(attrs[1].pValue);
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
    CK_MECHANISM mechanism = { 0, NULL_PTR, 0 };
    CK_BYTE hash[64], signature[1024], *to_sign;
    CK_ULONG hlen = sizeof(hash), slen = sizeof(signature);
    uasn1_item_t *sig, *padding = uasn1_sequence_new(2), *algoid = uasn1_sequence_new(2);
    CK_RV rc;
    uasn1_buffer_t *padbuf = uasn1_buffer_new(128);

    switch (digest) {
        case UASN1_SHA1:
            mechanism.mechanism = CKM_SHA_1;
            uasn1_add(algoid, uasn1_oid_new(id_sha1, 6));
            break;
        case UASN1_SHA256:
            mechanism.mechanism = CKM_SHA256;
            uasn1_add(algoid, uasn1_oid_new(id_sha256, 9));
            break;
        case UASN1_SHA384:
            mechanism.mechanism = CKM_SHA384;
            uasn1_add(algoid, uasn1_oid_new(id_sha384, 9));
            break;
        case UASN1_SHA512:
            mechanism.mechanism = CKM_SHA512;
            uasn1_add(algoid, uasn1_oid_new(id_sha512, 9));
            break;
    }

    rc = key->pkcs11.functions->C_DigestInit(key->pkcs11.session, &mechanism);
    if (rc != CKR_OK) {
        return NULL;
    }

    rc = key->pkcs11.functions->C_Digest(key->pkcs11.session, buffer->buffer, buffer->current, hash, &hlen);
    if (rc != CKR_OK) {
        return NULL;
    }

    if (key->pkcs11.type == CKK_RSA) {
        mechanism.mechanism = CKM_RSA_PKCS;

        uasn1_add(algoid, uasn1_item_new(uasn1_null_type));
        uasn1_add(padding, algoid);
        uasn1_add(padding, uasn1_octet_string_new(hash, hlen));
        uasn1_encode(padding, padbuf);
        to_sign = padbuf->buffer;
        hlen = padbuf->current;
        uasn1_write_buffer(padbuf, "padding.der");
    } else if (key->pkcs11.type == CKK_EC) {
        mechanism.mechanism = CKM_ECDSA;
        to_sign = hash;
    }

    rc = key->pkcs11.functions->C_SignInit(key->pkcs11.session, &mechanism, key->pkcs11.object);
    if (rc != CKR_OK) {
        return NULL;
    }

    rc = key->pkcs11.functions->C_Sign(key->pkcs11.session, to_sign, hlen, signature, &slen);
    if (rc != CKR_OK) {
        return NULL;
    }

    if (key->pkcs11.type == CKK_RSA) {
        sig  = uasn1_bit_string_new(signature, slen, 0);
    } else if (key->pkcs11.type == CKK_EC) {
        uasn1_buffer_t *buf = uasn1_buffer_new(256);
        uasn1_item_t *ec_sig = uasn1_sequence_new(2);
        uasn1_add(ec_sig, uasn1_large_integer_new(uasn1_integer_type, signature, slen / 2));
        uasn1_add(ec_sig, uasn1_large_integer_new(uasn1_integer_type, signature + slen /2, slen / 2));
        uasn1_encode(ec_sig, buf);
        sig = uasn1_bit_string_new(buf->buffer, buf->current, 0);
        uasn1_buffer_free(buf);
        uasn1_free(ec_sig);
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

int uasn1_x509_sign_new(uasn1_item_t *tbs,
                        uasn1_key_t *key,
                        uasn1_digest_t digest,
                        uasn1_buffer_t *buffer)
{
    uasn1_buffer_t *buff = uasn1_buffer_new(64);
    uasn1_item_t *certificate = uasn1_sequence_new(3);
    uasn1_item_t *signature, *tbs2, *algoid;
    int rv;

    uasn1_encode(tbs, buff);

    tbs2 = uasn1_preencoded(buff);
    uasn1_add(certificate, tbs2);

    algoid = uasn1_x509_algorithm(key, digest);
    uasn1_add(certificate, algoid);

    signature = uasn1_key_x509_sign(key, digest, buff);
    uasn1_add(certificate, signature);

    rv = uasn1_encode(certificate, buffer);

    uasn1_free(certificate);
    uasn1_buffer_free(buff);
    return rv;
}
