/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "uasn1.h"

#include <string.h>

int uasn1_encode_length(unsigned int length, uasn1_buffer_t *buffer)
{
    unsigned char l[5];
    int rv = 0;
    int i = 0;
    if(length < 0x80) {
        l[0] = length;
    } else {
        /* Ugly kludge to 32 bits... */
        do {
            l[i] = (unsigned char)(length & 0xFF);
            length >>= 8;
            i++;
        } while(length);
        /* We have i octets and we set high bit... */
        l[i] = i + 0x80;
    }

    do {
        rv = uasn1_buffer_put(buffer, l[i]);
    } while ((i--) && (rv == 0));
    return rv;
}

unsigned int uasn1_length_length(unsigned int length)
{
    unsigned int l = 1;
    if (length >= 0x80) {
        for(l = 2; (length = length >> 8); l++);
    }
    return l;
}

unsigned int uasn1_integer_length(uasn1_item_t *integer,
                                  int *padding, unsigned char *padval)
{
    unsigned int i = 0, neg = 0;
    unsigned int size = 0;
    int pad = 0;
    unsigned char pb = 0;

    neg = integer->value.string.flags;
    if (integer->value.string.size == 0) {
        size = 1;
    } else {
        size = integer->value.string.size;
        i = integer->value.string.string[0];
        if (! neg && (i > 127)) {
            pad = 1;
            pb = 0;
        } else if(neg) {
            if(i > 128) {
                pad = 1;
                pb = 0xFF;
            } else if(i == 128) {
                /*
                 * Special case: if any other bytes non zero we pad:
                 * otherwise we don't.
                 */
                for(i = 1; i < integer->value.string.size; i++) {
                    if(integer->value.string.string[i]) {
                        pad = 1;
                        pb = 0xFF;
                        break;
                    }
                }
            }
        }
        size += pad;
    }

    if(padding !=NULL)
        *padding = pad;
    if(padval != NULL)
        *padval = pb;
    return size;
}

unsigned int uasn1_item_length(uasn1_item_t *element)
{
    unsigned int length = 0;
    unsigned int i, j;

    if((element->tag.type == uasn1_end_of_content) ||
       (element->tag.type == uasn1_null_type)) {
        length = 0;
    } else if(element->tag.type == uasn1_boolean_type) {
        length = 1;
    } else if((element->tag.type == uasn1_integer_type) ||
              (element->tag.type == uasn1_enumerated_type)) {
        length = uasn1_integer_length(element, NULL, NULL);
    } else if(element->tag.type == uasn1_oid_type) {
        length = 1;
        for(i = 2; (i < element->value.oid.size); i++) {
            j = element->value.oid.elements[i];
            do {
                length++;
                j >>= 7;
            } while (j);
        }
    } else if((element->tag.type == uasn1_sequence_type) ||
              (element->tag.type == uasn1_set_type)) {
        length = 0;
        for(i = 0; i < uasn1_count(element); i++) {
            uasn1_item_t *e;
            if((e = uasn1_get(element, i))) {
                if(e->tag.flags & uasn1_preencoded_type) {
                    length += e->value.string.size;
                } else {
                    unsigned int k = uasn1_item_length(e);
                    unsigned int l = k + 1 + uasn1_length_length(k);
                    length += l;
                    if (e->tag.tag == uasn1_explicit_tag) {
                        length += 1 + uasn1_length_length(l);
                    }
                }
            }
        }
    } else {
        length = element->value.string.size;
        if(element->tag.type == uasn1_bit_string_type) {
            length++;
        }
    }
    return length;
}

int uasn1_oid_encode(uasn1_item_t *element,
                     uasn1_buffer_t *buffer)
{
    unsigned int i = 1, k, rv = 0;
    unsigned int j = element->value.oid.elements[0] * 40 +
        element->value.oid.elements[1];
    int l;

    do {
        if(i != 1) {
            j = element->value.oid.elements[i];
        }
        for (k = j, l = 0; (k & (~ 0x7F)) ; k = k >> 7, l++);
        for(;(rv == 0) && (l >= 0); l--) {
            unsigned char c = (j >> (7 * l)) & 0x7F;
            rv = uasn1_buffer_put(buffer, (l) ? c | 0x80 : c);
        }
        i++;
    } while ((rv == 0) && (i < element->value.oid.size));
    return rv;
}

/*
 * This converts an ASN1Integer into its content encoding.  The
 * internal representation is an ASN1_STRING whose data is a big
 * endian representation of the value, ignoring the sign. The sign is
 * determined by the neg field: zero for positive and non-zero for
 * negative.
 *
 * Positive integers are no problem: they are almost the same as the
 * DER encoding, except if the first byte is >= 0x80 we need to add a
 * zero pad.
 *
 * Negative integers are a bit trickier...
 * The DER representation of negative integers is in 2s complement
 * form.  The internal form is converted by complementing each octet
 * and finally adding one to the result. This can be done less messily
 * with a little trick.  If the internal form has trailing zeroes then
 * they will become FF by the complement and 0 by the add one (due to
 * carry) so just copy as many trailing zeros to the destination as
 * there are in the source. The carry will add one to the last none
 * zero octet: so complement this octet and add one and finally
 * complement any left over until you get to the start of the string.
 *
 * Padding is a little trickier too. If the first bytes is > 0x80 then
 * we pad with 0xff. However if the first byte is 0x80 and one of the
 * following bytes is non-zero we pad with 0xff. The reason for this
 * distinction is that 0x80 followed by optional zeros isn't padded.
 */
int uasn1_integer_encode(uasn1_item_t *integer,
                         uasn1_buffer_t *buffer)
{
    int rv = 0, i;
    unsigned int size;
    unsigned char *p = 0, *op, *n, pb = 0;

    if ((integer == NULL) || (integer->value.string.string == NULL))
        return 0;

    size = uasn1_integer_length(integer, &rv, &pb);

    op = (unsigned char *) malloc(size * sizeof(unsigned char));
    if (op == NULL) { return 0; }
    p = op;

    if (rv) *(p++) = pb;
    if (integer->value.string.size == 0) {
        *(p++)=0;
    } else {
        if (!(integer->value.string.flags)) {
            memcpy(p, integer->value.string.string, integer->value.string.size);
        } else {
            /* Begin at the end of the encoding */
            n = integer->value.string.string +
                integer->value.string.size - 1;
            p += integer->value.string.size - 1;
            i = integer->value.string.size;
            /* Copy zeros to destination as long as source is zero */
            while(!*n) {
                *(p--) = 0;
                n--;
                i--;
            }
            /* Complement and increment next octet */
            *(p--) = ((*(n--)) ^ 0xff) + 1;
            i--;
            /* Complement any octets left */
            for(;i > 0; i--) {
                *(p--) = *(n--) ^ 0xff;
            }
        }
    }

    rv = uasn1_buffer_push(buffer, op, size);
    free(op);
    return rv;
}

int uasn1_encode(uasn1_item_t *element,
                 uasn1_buffer_t *buffer)
{
    int rv = 0, i;
    unsigned length = uasn1_item_length(element);
    int indefinite = 0;

    if((((element->tag.type == uasn1_sequence_type) ||
         (element->tag.type == uasn1_set_type))) &&
       (element->tag.flags == uasn1_indefinite_type)) {
        indefinite = 2;
    }


    /* Special case for pre-encoded elements */
    if(element->tag.flags == uasn1_preencoded_type) {
        return uasn1_buffer_push(buffer,
                                 element->value.string.string,
                                 element->value.string.size);
    }

    /* Tag encoding */
    if(element->tag.tag == uasn1_implicit_tag) {
        uasn1_buffer_put(buffer, (element->tag._class |
                                  element->tag.value |
                                  element->tag.construct) & 0xFF );
    } else {
        if(element->tag.tag == uasn1_explicit_tag) {
            uasn1_buffer_put(buffer, (element->tag._class |
                                      element->tag.value |
                                      uasn1_constructed_tag ) & 0xFF );
            if(indefinite) {
                uasn1_buffer_put(buffer, 0x80);
                indefinite += 2;
            } else{
                uasn1_encode_length(length + uasn1_length_length(length) + 1, buffer);
            }
        }
        uasn1_buffer_put(buffer, (element->tag.type |
                                  element->tag.construct) & 0xFF );
    }

    /* Length encoding */
    if(indefinite) {
        uasn1_buffer_put(buffer, 0x80);
    } else {
        uasn1_encode_length(length, buffer);
    }

    /* Value encoding */
    if((element->tag.type == uasn1_end_of_content) ||
       (element->tag.type == uasn1_null_type)) {
        /* Nothing to do in this case */
    } else if(element->tag.type == uasn1_boolean_type) {
        rv = uasn1_buffer_put(buffer, ((element->value.numeric == uasn1_false) ?
                                       uasn1_false : uasn1_true));
    } else if(element->tag.type == uasn1_oid_type) {
        rv = uasn1_oid_encode(element, buffer);
    } else if((element->tag.type == uasn1_integer_type) ||
              (element->tag.type == uasn1_enumerated_type)) {
        rv = uasn1_integer_encode(element, buffer);
    } else if((element->tag.type == uasn1_sequence_type) ||
              (element->tag.type == uasn1_set_type)) {
        /* TODO: add sorting for sets */
        unsigned int i, j = uasn1_count(element);
        for(i = 0; (i < j) && (rv == 0) ; i++) {
            rv = uasn1_encode(uasn1_get(element, i), buffer);
        }
    } else {
        if (element->tag.type == uasn1_bit_string_type) {
            rv = uasn1_buffer_put(buffer, (element->value.string.flags));
            if(rv) return rv;
        }
        rv = uasn1_buffer_push(buffer,
                               element->value.string.string,
                               element->value.string.size);
    }

    for(i = 0; i < indefinite; i++) {
        uasn1_buffer_put(buffer, 0x00);
    }

    return rv;
}

uasn1_item_t *uasn1_to_octet_string(uasn1_item_t *element)
{
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);
    uasn1_item_t *rv;
    uasn1_encode(element, buffer);
    rv = uasn1_octet_string_new(buffer->buffer, buffer->current);
    uasn1_buffer_free(buffer);
    return rv;
}
