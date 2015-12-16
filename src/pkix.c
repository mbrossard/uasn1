/*
 * Copyright © 2015 Mathias Brossard
 */

#include <string.h>

#include "uasn1.h"
#include "utils.h"
#include "sign.h"
#include "oids.h"
#include "x509.h"
#include "pkix.h"

void uasn1_x509_add_key_usage(uasn1_item_t *extensions,
                              unsigned char critical,
                              unsigned int keyusage)
{
    unsigned int size = 1, max;
    unsigned char buf[2];
    uasn1_item_t *bs;

    buf[0] = (keyusage >> 8) & 0xFF;

    if((buf[1] = (keyusage & 0xFF))) {
        size = 2;
        max = 9;
    } else {
        int i = 0;
        max = 8;
        for (; (((buf[0] >> i) & 1) == 0) && (max != 0); i++, max--);
    }
    bs = uasn1_bit_string_new(buf, size, 8 - max);
    uasn1_add_x509_extension(extensions, "keyUsage", critical, bs);
    uasn1_free(bs);
}

void uasn1_x509_add_ext_key_usage(uasn1_item_t *extensions,
                                  unsigned char critical,
                                  char **usages)
{
    unsigned int i, j;
    uasn1_item_t *sequence;

    for (j = 0; usages[j] != NULL; j++);
    sequence = uasn1_sequence_new(j);
    for (i = 0; i < j ; i++) {
        uasn1_add(sequence, uasn1_get_oid_by_name(usages[i]));
    }
    uasn1_add_x509_extension(extensions, "extKeyUsage",
                           critical, sequence);
    uasn1_free(sequence);
}


void uasn1_x509_add_subject_alt_name(uasn1_item_t *extensions,
                                     unsigned char critical,
                                     unsigned int length,
                                     void **values,
                                     int *type)
{
    uasn1_item_t *subjectAltName = uasn1_sequence_new(1);
    unsigned int i;

    for(i = 0; i < length; i++) {
        uasn1_item_t *value = NULL;

        switch(type[i]) {
            case otherName:
            case x400Address:
            case directoryName:
            case ediPartyName:
            case iPAddress:
            case registeredID:
                value = (uasn1_item_t *)values[i];
                break;

            case rfc822Name:
            case dNSName:
            case uniformResourceIdentifier:
                value = uasn1_ia5_string_new((unsigned char*)values[i],
                                             strlen((char*)values[i]));
                break;

            default:
                break;
        }

        if(value) {
            uasn1_set_tag(value, uasn1_context_specific_tag,
                          type[i], uasn1_implicit_tag);
            uasn1_add(subjectAltName, value);
        }
    }

    uasn1_add_x509_extension(extensions, "subjectAltName",
                           critical, subjectAltName);

    uasn1_free(subjectAltName);
}


void uasn1_x509_add_basic_constraints(uasn1_item_t *extensions,
                                      unsigned char critical,
                                      unsigned char ca,
                                      unsigned char pathLen,
                                      unsigned int length)
{
    uasn1_item_t *basicConstraints = uasn1_sequence_new(2);
    if(ca != uasn1_false) {
        uasn1_add(basicConstraints, uasn1_boolean_new(ca));
    }
    if(pathLen != uasn1_false) {
        uasn1_add(basicConstraints, uasn1_integer_new(length));
    }
    uasn1_add_x509_extension(extensions, "basicConstraints",
                             critical, basicConstraints);
    uasn1_free(basicConstraints);
}

void uasn1_x509_add_ski(uasn1_item_t *extensions,
                        unsigned char critical,
                        uasn1_item_t *key)
{
    uasn1_item_t *key_sha1 = sha1ASN1Element(key);
    uasn1_add_x509_extension(extensions, "subjectKeyIdentifier",
                             critical, key_sha1);
    uasn1_free(key_sha1);
}

void uasn1_x509_add_aki(uasn1_item_t *extensions,
                        unsigned char critical,
                        uasn1_item_t *key)
{
    uasn1_item_t *key_sha1 = sha1ASN1Element(key);
    uasn1_add_x509_extension(extensions, "authorityKeyIdentifier",
                             critical, key_sha1);
    uasn1_free(key_sha1);
}

uasn1_x509_sda_t sdadb[] = {
    { "dateOfBirth",          uasn1_generalized_time_type },
    { "placeOfBirth",         uasn1_printable_string_type },
    { "gender",               uasn1_printable_string_type },
    { "countryOfCitizenship", uasn1_printable_string_type },
    { "countryOfResidence",   uasn1_printable_string_type }
};

uasn1_item_t *uasn1_x509_subject_directory_attribute(char *name, char *value,
                                                     uasn1_type_t type)
{
    uasn1_item_t *set = uasn1_set_new(1);
    uasn1_item_t *sequence = uasn1_sequence_new(2);

    uasn1_add(sequence, uasn1_get_oid_by_name(name));
    uasn1_add(sequence, set);
    uasn1_add(set, uasn1_string_new(type, (unsigned char *)value, strlen(value)));
    return sequence;
}

void uasn1_x509_add_subject_directory_attribute(uasn1_item_t *extensions,
                                                uasn1_x509_sda_t *elements)
{
    unsigned int i;
    uasn1_item_t *sequence;

    for (i = 0; elements[i].value != NULL; i++);

    sequence = uasn1_sequence_new(i);

    for (i = 0; elements[i].value != NULL; i++) {
        unsigned int j = elements[i].type;
        if(j < maxSDA) {
            uasn1_item_t *dsa_element = uasn1_x509_subject_directory_attribute
                (sdadb[j].value, elements[i].value, sdadb[j].type);
            uasn1_add(sequence, dsa_element);
		}
	}

    uasn1_add_x509_extension(extensions, "subjectDirectoryAttributes",
                             0 ,uasn1_to_octet_string(sequence));
}
