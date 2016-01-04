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
