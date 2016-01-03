/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "cryptoki.h"

#include <stdio.h>
#include <string.h>
#include <memory.h>

#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
#ifdef __APPLE__
#include <Carbon/Carbon.h>
#endif

#include <sys/types.h>
#include <dlfcn.h>
#include <stdlib.h>
#else
#include <windows.h>
#endif

#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
CK_FUNCTION_LIST  *pkcs11_get_function_list(const char *param)
{
    CK_FUNCTION_LIST  *funcs;
    CK_RV            (*get_fun)();
    void              *d;
    const char        *e = param ? param : getenv("PKCS11_LIBRARY");
    e = e ? e : DEFAULT_PKCS11_MODULE;

    d = dlopen(e, RTLD_LAZY);
    if (d == NULL) {
        fprintf(stdout, "dlopen('%s') failed\n", e);
        return NULL;
    }
    *(void **) (&get_fun) = dlsym(d, "C_GetFunctionList");
    if (get_fun == NULL) {
        fprintf(stdout, "Symbol lookup failed\n");
        return NULL;
    }
    CK_RV rc = get_fun(&funcs);
    if (rc != CKR_OK) {
        funcs = NULL;
    } else if(funcs == NULL) {
        fprintf(stdout, "C_GetFunctionList returned empty value\n");
    }
    return funcs;
}
#else
CK_FUNCTION_LIST  *pkcs11_get_function_list(const char *param)
{
    CK_FUNCTION_LIST  *funcs;
    void              *d;
    const char        *e = param ? param : getenv("PKCS11_LIBRARY");
    e = e ? e : DEFAULT_PKCSLIB;

    d = LoadLibrary(e);
    if (d == NULL) {
        fprintf(stdout, "LoadLibrary Failed\n");
        return NULL;
    }

#ifndef USE_GET_FUNCTION_LIST
    /* Look-up all symbols from dll */
    funcs = (CK_FUNCTION_LIST_PTR) malloc(sizeof(CK_FUNCTION_LIST));
    if(funcs) {
#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO
#define CK_PKCS11_FUNCTION_INFO(name)                       \
        if((funcs->name = (CK_RV (*)())GetProcAddress(d, #name)) == NULL) { \
            fprintf(stdout, "Error looking up %s\n", #name); \
            free(funcs); \
            return NULL; \
        }
#include "pkcs11f.h"
    }
#else
    /* Look-up C_GetFunctionList and use it to get all functions */
    CK_RV            (*get_fun)();
    get_fun = (CK_RV (*)())GetProcAddress(d, "C_GetFunctionList");
    if (get_fun == NULL) {
        fprintf(stdout, "Symbol lookup failed\n");
        return NULL;
    }
    CK_RV rc = get_fun(&funcs);
    if (rc != CKR_OK) {
        funcs = NULL;
    } else if(funcs == NULL) {
        fprintf(stdout, "C_GetFunctionList returned empty value\n");
    }
#endif
    return funcs;
}
#endif

unsigned char prime256v1_oid[] = { 0x06, 0x08, 0x2a, 0x86, 0x48,
                                   0xce, 0x3d, 0x03, 0x01, 0x07 };
unsigned char secp384r1_oid[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
unsigned char secp521r1_oid[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };

CK_RV pkcs11_initialize_nss(CK_FUNCTION_LIST_PTR funcs, const char *path)
{
    CK_RV rc = CKR_HOST_MEMORY;
    static const char *nss_init_string = "configdir='%s' certPrefix='' keyPrefix='' secmod='secmod.db'";

    char buffer[256];
    CK_C_INITIALIZE_ARGS *iap = NULL;
    struct {
        CK_CREATEMUTEX CreateMutex;
        CK_DESTROYMUTEX DestroyMutex;
        CK_LOCKMUTEX LockMutex;
        CK_UNLOCKMUTEX UnlockMutex;
        CK_FLAGS flags;
        CK_CHAR_PTR LibraryParameters;
        CK_VOID_PTR pReserved;
    } ia;

    iap = (CK_C_INITIALIZE_ARGS *)&ia;
    ia.flags = CKF_OS_LOCKING_OK;
    ia.LibraryParameters = (CK_CHAR_PTR)buffer;
    ia.pReserved = NULL_PTR;
    snprintf(buffer, 256, nss_init_string, path);
    rc = funcs->C_Initialize((CK_VOID_PTR)iap);

    return rc;
}

CK_RV pkcs11_initialize(CK_FUNCTION_LIST_PTR funcs, const char *path)
{
    CK_RV rc = CKR_HOST_MEMORY;

    if (funcs) {
        if (path) {
            rc = pkcs11_initialize_nss(funcs, path);
        } else {
            rc = funcs->C_Initialize(NULL);
            if (rc == CKR_ARGUMENTS_BAD) {
                rc = pkcs11_initialize_nss(funcs, ".");
            }
        }
    }
    return rc;
}


void print_usage_and_die(const char *name, const struct option *opts, const char **help)
{
    int i = 0;
    fprintf(stdout, "Usage: %s [OPTIONS]\nOptions:\n", name);

    while (opts[i].name) {
        char buf[40], tmp[5];
        const char *arg_str;

        /* Skip "hidden" opts */
        if (help[i] == NULL) {
            i++;
            continue;
        }

        if (opts[i].val > 0 && opts[i].val < 128)
            sprintf(tmp, ", -%c", opts[i].val);
        else
            tmp[0] = 0;
        switch (opts[i].has_arg) {
            case 1:
                arg_str = " <arg>";
                break;
            case 2:
                arg_str = " [arg]";
                break;
            default:
                arg_str = "";
                break;
        }
        sprintf(buf, "--%s%s%s", opts[i].name, tmp, arg_str);
        if (strlen(buf) > 29) {
            fprintf(stdout, "  %s\n", buf);
            buf[0] = '\0';
        }
        fprintf(stdout, "  %-29s %s\n", buf, help[i]);
        i++;
    }
    exit(2);
}


CK_RV pkcs11_get_slots(CK_FUNCTION_LIST_PTR funcs,
                       CK_SLOT_ID_PTR *slots,
                       CK_ULONG_PTR nslots)
{
    CK_SLOT_ID *s;
    CK_ULONG n;
    CK_RV rc;

    if(!slots || !nslots) {
        return CKR_ARGUMENTS_BAD;
    }

    rc = funcs->C_GetSlotList(0, NULL_PTR, &n);
    if (rc != CKR_OK) {
        return rc;
    }
    s = malloc(sizeof(CK_SLOT_ID) * n);
    rc = funcs->C_GetSlotList(0, s, &n);
    if (rc != CKR_OK) {
        return rc;
    }

    *slots = s;
    *nslots = n;

    return rc;
}

CK_RV pkcs11_check_slot(CK_FUNCTION_LIST_PTR funcs, CK_SLOT_ID slot)
{
    CK_SLOT_ID        *pslots = NULL;
    CK_ULONG          nslots, islot;
    CK_RV             rc;

    rc = pkcs11_get_slots(funcs, &pslots, &nslots);
    if (rc != CKR_OK) {
        return rc;
    }

    for(islot = 0; islot < nslots; islot++) {
        if(pslots[islot] == slot) {
            break;
        }
    }
    if(islot == nslots) {
        rc = CKR_SLOT_ID_INVALID;
    }

    return rc;
}

CK_RV pkcs11_init_token(CK_FUNCTION_LIST_PTR funcs, CK_SLOT_ID slot,
                        CK_UTF8CHAR_PTR label, CK_UTF8CHAR_PTR pin,
                        CK_ULONG pin_len)
{
    CK_SESSION_HANDLE h_session;
    CK_RV             rc;

    rc = funcs->C_InitToken(slot, NULL, 0, label);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = funcs->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &h_session);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = funcs->C_Login(h_session, CKU_SO, NULL, 0);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = funcs->C_InitPIN(h_session, pin, pin_len);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = funcs->C_Logout(h_session);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = funcs->C_CloseSession(h_session);
    return rc;
}

CK_RV pkcs11_find_object(CK_FUNCTION_LIST_PTR funcs,
                         CK_SESSION_HANDLE h_session,
                         CK_ATTRIBUTE_PTR search, CK_ULONG length,
                         CK_OBJECT_HANDLE_PTR objects,
                         CK_ULONG count, CK_ULONG_PTR found)
{
    CK_ULONG f = 0;
    CK_RV rc;

    rc = funcs->C_FindObjectsInit(h_session, search, length);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = funcs->C_FindObjects(h_session, objects, count, &f);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        return rc;
    }

    if(found) {
        *found = f;
    }

    return rc;
}

CK_RV pkcs11_login_session(CK_FUNCTION_LIST_PTR funcs, CK_SLOT_ID slot,
                           CK_SESSION_HANDLE_PTR session,
                           CK_BBOOL readwrite, CK_USER_TYPE user,
                           CK_UTF8CHAR_PTR pin, CK_ULONG pinLen)
{
    CK_SESSION_HANDLE h_session;
    CK_FLAGS flags = CKF_SERIAL_SESSION | (readwrite ? CKF_RW_SESSION : 0);
    CK_RV rc;

    rc = funcs->C_OpenSession(slot, flags, NULL, NULL, &h_session);
    if (rc != CKR_OK) {
        return rc;
    }

    if(pin) {
        rc = funcs->C_Login(h_session, user, pin, pinLen);
        if (rc != CKR_OK) {
            goto end;
        }
    } else if(readwrite || pinLen > 0) {
        CK_TOKEN_INFO  info;

        rc = funcs->C_GetTokenInfo(slot, &info);
        if (rc != CKR_OK) {
            goto end;
        }
        
        if(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
            rc = funcs->C_Login(h_session, user, NULL, 0);
            if (rc != CKR_OK) {
                goto end;
            }
        }
    }

 end:
    if (rc != CKR_OK) {
        /* We want to keep the original error code */
        CK_RV r = funcs->C_CloseSession(h_session);
    } else if(session) {
        *session = h_session;
    }
    return rc;
}

void pkcs11_fill_attribute(CK_ATTRIBUTE *attr, CK_ATTRIBUTE_TYPE type,
                           CK_VOID_PTR pvoid, CK_ULONG ulong)
{
	attr->type = type;
	attr->pValue =  pvoid;
	attr->ulValueLen = ulong;
}

CK_RV pkcs11_load_init(const char *module, const char *path,
                       CK_FUNCTION_LIST_PTR *funcs)
{
    CK_RV rc = CKR_GENERAL_ERROR;
    CK_FUNCTION_LIST_PTR f;

    if(funcs == NULL) {
        return rc;
    }

    f = pkcs11_get_function_list(module);
    if (!f) {
        return rc;
    }

    rc = pkcs11_initialize(f, path);
    if (rc != CKR_OK) {
        return rc;
    }

    *funcs = f;
    return rc;
}

CK_RV pkcs11_close(CK_FUNCTION_LIST_PTR funcs,
                   CK_SESSION_HANDLE h_session)
{
    CK_RV rc = funcs->C_Logout(h_session);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = funcs->C_CloseSession(h_session);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        return rc;
    }

    return rc;
}


CK_RV pkcs11_set_key_id(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session,
                        CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey,
                        CK_ATTRIBUTE_PTR attrs, CK_BYTE_PTR label)
{
	CK_RV rc = CKR_HOST_MEMORY;
    CK_ATTRIBUTE kid[2];
    int i = 0;

    CK_BYTE buf[20];
    CK_ULONG len = sizeof(buf);
    CK_MECHANISM mechanism = { CKM_SHA_1, NULL_PTR, 0 };
    
    rc = funcs->C_DigestInit(session, &mechanism);
    if (rc != CKR_OK) {
        return rc;
    }
    rc = funcs->C_Digest(session, attrs[0].pValue, attrs[0].ulValueLen, buf, &len);

    if(label) {
        pkcs11_fill_attribute(&(kid[i++]), CKA_LABEL,
                              label, strlen((char *)label));
    }

    rc = funcs->C_SetAttributeValue(session, hPrivateKey, kid, i);
    if (rc == CKR_OK) {
        rc = funcs->C_SetAttributeValue(session, hPublicKey , kid, i);
    }

	return rc;
}

CK_RV pkcs11_generate_key_pair(CK_FUNCTION_LIST_PTR funcs,
                               CK_SESSION_HANDLE session,
                               CK_KEY_TYPE type, CK_ULONG size,
                               CK_BYTE_PTR label,
                               CK_OBJECT_HANDLE_PTR hPub,
                               CK_OBJECT_HANDLE_PTR hPrv)
{
    CK_RV rc = CKR_HOST_MEMORY;
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_BBOOL t = TRUE;
    CK_OBJECT_CLASS	prv = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS pub = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE attrs[2] = {
        { 0, NULL, 0},
        { 0, NULL, 0},
    };

	if(!funcs) {
        return rc;
    }

    if(type == CKK_RSA) {
        CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_BYTE exponent[3] = { 0x01, 0x00, 0x01 };
        CK_ATTRIBUTE publicKeyTemplate[8] = {
            { CKA_CLASS ,          &pub,      sizeof(pub)      },
            { CKA_KEY_TYPE,        &type,     sizeof(type)     },
            { CKA_TOKEN,           &t,        sizeof(CK_BBOOL) },
            { CKA_ENCRYPT,         &t,        sizeof(CK_BBOOL) },
            { CKA_VERIFY,          &t,        sizeof(CK_BBOOL) },
            { CKA_WRAP,            &t,        sizeof(CK_BBOOL) },
            { CKA_MODULUS_BITS,    &size,     sizeof(size)     },
            { CKA_PUBLIC_EXPONENT, &exponent, sizeof(exponent) },
        };
        CK_ATTRIBUTE privateKeyTemplate[8] = {
            { CKA_CLASS,      &prv,       sizeof(prv)       },
            { CKA_KEY_TYPE,   &type,      sizeof(type)      },
            { CKA_TOKEN,      &t,         sizeof(CK_BBOOL)  },
            { CKA_PRIVATE,    &t,         sizeof(CK_BBOOL)  },
            { CKA_SENSITIVE,  &t,         sizeof(CK_BBOOL)  },
            { CKA_DECRYPT,    &t,         sizeof(CK_BBOOL)  },
            { CKA_SIGN,       &t,         sizeof(CK_BBOOL)  },
            { CKA_UNWRAP,     &t,         sizeof(CK_BBOOL)  },
        };

        if((rc = funcs->C_GenerateKeyPair
            (session, &mechanism, publicKeyTemplate, 8,
             privateKeyTemplate, 8, &hPublicKey, &hPrivateKey)) != CKR_OK) {
            goto done;
        }

        if((hPublicKey  == CK_INVALID_HANDLE) ||
           (hPrivateKey == CK_INVALID_HANDLE)) {
            rc = CKR_HOST_MEMORY; /* */
            goto done;
        }

        pkcs11_fill_attribute(&attrs[0], CKA_PUBLIC_EXPONENT, NULL, 0);
        pkcs11_fill_attribute(&attrs[1], CKA_MODULUS,         NULL, 0);

        if ((rc = funcs->C_GetAttributeValue
             (session, hPublicKey, attrs, 2)) != CKR_OK) {
            goto done;
        }

        if (((attrs[0].pValue = malloc(attrs[0].ulValueLen)) == NULL) ||
            ((attrs[1].pValue = malloc(attrs[1].ulValueLen)) == NULL)) {
            rc = CKR_HOST_MEMORY;
            goto done;
        }

        if ((rc = funcs->C_GetAttributeValue
             (session, hPublicKey, attrs, 2)) != CKR_OK) {
            goto done;
        }
    } else if(type == CKK_EC) {
        CK_MECHANISM mechanism = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_ATTRIBUTE pubTemplate[2] = {
            { CKA_EC_PARAMS,  NULL, 0                 },
            { CKA_TOKEN,      &t,   sizeof(CK_BBOOL)  }
        };
        CK_ATTRIBUTE privTemplate[4] = {
            { CKA_TOKEN,      &t,   sizeof(CK_BBOOL)  },
            { CKA_PRIVATE,    &t,   sizeof(CK_BBOOL)  },
            { CKA_SENSITIVE,  &t,   sizeof(CK_BBOOL)  },
            { CKA_SIGN,       &t,   sizeof(CK_BBOOL)  }
        };

        switch(size) {
            case 256:
                privTemplate[0].pValue = prime256v1_oid;
                privTemplate[0].ulValueLen = sizeof(prime256v1_oid);
                break;
            case 384:
                privTemplate[0].pValue = secp384r1_oid;
                privTemplate[0].ulValueLen = sizeof(secp384r1_oid);
                break;
            case 521:
                privTemplate[0].pValue = secp521r1_oid;
                privTemplate[0].ulValueLen = sizeof(secp521r1_oid);
                break;
            default:
                return CKR_DOMAIN_PARAMS_INVALID;
        }

        pubTemplate[0].pValue = privTemplate[0].pValue;
        pubTemplate[0].ulValueLen = privTemplate[0].ulValueLen;

        if((rc = funcs->C_GenerateKeyPair
            (session, &mechanism, pubTemplate, 2,
             privTemplate, 4, &hPublicKey, &hPrivateKey)) != CKR_OK) {
            goto done;
        }

        if((hPublicKey  == CK_INVALID_HANDLE) ||
           (hPrivateKey == CK_INVALID_HANDLE)) {
            rc = CKR_HOST_MEMORY; /* Maybe there's something clearer */
            goto done;
        }

        pkcs11_fill_attribute(&attrs[0], CKA_EC_POINT, NULL, 0);
        if ((rc = funcs->C_GetAttributeValue
             (session, hPublicKey, attrs, 1)) != CKR_OK) {
            goto done;
        }

        if (((attrs[0].pValue = malloc(attrs[0].ulValueLen)) == NULL)) {
            rc = CKR_HOST_MEMORY;
            goto done;
        }

        if ((rc = funcs->C_GetAttributeValue
             (session, hPublicKey, attrs, 1)) != CKR_OK) {
            goto done;
        }
    }

    if(rc == CKR_OK) {
        rc = pkcs11_set_key_id(funcs, session, hPublicKey,
                               hPrivateKey, attrs, label);
    }

 done:
    free(attrs[0].pValue);
    free(attrs[1].pValue);

    if(rc == CKR_OK) {
        if(hPub) {
            *hPub = hPublicKey;
        }
        if(hPrv) {
            *hPrv = hPrivateKey;
        }
    }

    return rc;
}
