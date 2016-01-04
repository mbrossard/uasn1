#include "config.h"
#include "uasn1.h"
#include "crypto/cryptoki.h"

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

uasn1_item_t *uasn1_key_pkcs11_get_asn1_public_key(uasn1_key_t *key)
{
    uasn1_item_t *k = NULL;
    CK_ATTRIBUTE attrs[2] = {{ 0, NULL }, { 0, NULL }};
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

    return k;
}
