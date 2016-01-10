
#include "config.h"
#include "uasn1.h"
#include "crypto/key.h"
#include "crypto/cryptoki.h"
#include "crypto/pkcs11/crypto.h"

#ifdef HAVE_OPENSSL
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#endif

#include <string.h>

uasn1_key_t *uasn1_key_load(uasn1_crypto_t *crypto, uasn1_key_type_t type, char *label)
{
    if(crypto->provider == UASN1_PKCS11) {
        return uasn1_key_pkcs11_load(crypto, type, label);
    } else {
        return NULL;
    }
}

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
        key_info = uasn1_key_pkcs11_get_asn1_public_key_info(key);
    }

    return key_info;
}

uasn1_item_t *uasn1_key_get_key_identifier(uasn1_key_t *key)
{
    uasn1_item_t *ki = NULL;

    if(key->provider == UASN1_PKCS11) {
        ki = uasn1_key_pkcs11_get_key_identifier(key);
    }

    return ki;
}

static unsigned int id_sha1[6] = { 1, 3, 14, 3, 2, 26 };
static unsigned int id_sha256[9] = { 2, 16, 840, 1, 101, 3, 4, 2, 1 };
static unsigned int id_sha384[9] = { 2, 16, 840, 1, 101, 3, 4, 2, 2 };
static unsigned int id_sha512[9] = { 2, 16, 840, 1, 101, 3, 4, 2, 3 };

uasn1_item_t *uasn1_digest_octet_string(uasn1_crypto_t *crypto, uasn1_digest_t digest, void *data, size_t length)
{
    if(crypto->provider == UASN1_PKCS11) {
        return uasn1_digest_pkcs11_octet_string(crypto, digest, data, length);
    } else {
        return NULL;
    }
}

uasn1_item_t *uasn1_hash_buffer_to_octet_string(uasn1_crypto_t *crypto, uasn1_digest_t digest, uasn1_buffer_t *buffer)
{
    return uasn1_digest_octet_string(crypto, digest, buffer->buffer, buffer->current);
}

uasn1_item_t *uasn1_hash_to_octet_string(uasn1_crypto_t *crypto, uasn1_digest_t digest, uasn1_item_t *item)
{
    uasn1_item_t *hash = NULL;
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);
    uasn1_encode(item, buffer);
    hash = uasn1_digest_octet_string(crypto, digest, buffer->buffer, buffer->current);
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
    uasn1_item_t *algoid = NULL;
    uasn1_asymetric_t type = -1;
    unsigned int sha1withRSAEncryption[7] = { 1, 2, 840, 113549, 1, 1, 5 };
    unsigned int sha256withRSAEncryption[7] = { 1, 2, 840, 113549, 1, 1, 11 };
    unsigned int sha384withRSAEncryption[7] = { 1, 2, 840, 113549, 1, 1, 12 };
    unsigned int sha512withRSAEncryption[7] = { 1, 2, 840, 113549, 1, 1, 13 };
    unsigned int ecdsaWithSHA256[7] = { 1, 2, 840, 10045, 4, 3, 2 };

    if(key->provider == UASN1_PKCS11) {
        type = uasn1_key_pkcs11_type(key);
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
    uasn1_item_t *algoid = NULL;
    uasn1_asymetric_t type = -1;
    unsigned int rsaEncryption[7] = { 1, 2, 840, 113549, 1, 1, 1 };
    unsigned int ecdsaWithSHA256[7] = { 1, 2, 840, 10045, 4, 3, 2 };

    if(key->provider == UASN1_PKCS11) {
        type = uasn1_key_pkcs11_type(key);
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
