/*
 * Copyright © 2015 Mathias Brossard
 */

#include "uasn1.h"

#include <string.h>

unsigned int uasn1_decode_length(uasn1_buffer_t *buffer)
{
    unsigned int rv = 0;
    unsigned char c = uasn1_buffer_get(buffer);

    if(c <= 127) {
        rv = c;
    } else {
        int i = c - 128;
        /* Ugly kludge to 32 bits... */
        for(i = 0; i < (c - 128); i++) {
            rv = rv << 8;
            rv |= uasn1_buffer_get(buffer);
        }
    }
    return rv;
}

uasn1_item_t *uasn1_decode_tag(uasn1_buffer_t *buffer)
{
    uasn1_item_t *element;
    unsigned char c = uasn1_buffer_get(buffer);
    unsigned char type, tag;
    unsigned char _class = c & uasn1_class_mask;
    unsigned char value = c & ~(uasn1_class_mask | uasn1_constructed_tag);

    if(_class != uasn1_universal_tag) {
        if (c & uasn1_constructed_tag) {
            tag = uasn1_explicit_tag;
            uasn1_decode_length(buffer);
            c = uasn1_buffer_get(buffer);
            type = c & ~ (uasn1_class_mask | uasn1_constructed_tag);
        } else {
            tag = uasn1_implicit_tag;
            type = uasn1_octet_string_type; /* Lets use that as default */
        }
    } else {
        tag = uasn1_no_tag;
        type = value;
        value = 0;
    }
    element = uasn1_item_new(type);
    if (element) {
        element->tag._class = _class;
        element->tag.value = value;
        element->tag.tag = tag;
        element->tag.construct = (c & uasn1_constructed_tag) ?
            uasn1_constructed_tag : uasn1_primitive_tag;
    }
    return element;
}

uasn1_item_t *uasn1_decode_oid(uasn1_item_t *element,
                               uasn1_buffer_t *buffer,
                               unsigned int length)
{
    unsigned int i, j = 1;
    unsigned int *v;
    unsigned char c;

    /* Protection against buffer overflow */
    if((buffer->current - buffer->seek) < length) {
        length = buffer->current - buffer->seek;
    }

    /* How many elements ? */
    for(i = 0; i < length; i++) {
        if((buffer->buffer[i + buffer->seek] < 0x80)) j++;
    }

    v = (unsigned int *) malloc(( j )* sizeof(unsigned int));
    i = 1;
    do {
        c = uasn1_buffer_get(buffer);
        if(i == 1) {
            v[0] = c / 40;
            v[1] = c % 40;
        } else {
            v[i] = (v[i] << 7) | (c & 0x7F);
        }

        if (c < 0x80) {
            i++;
            if(i < j) {
                v[i] = 0;
            }
        }
    } while(i < j);
    element->value.oid.elements = v;
    element->value.oid.size = j;
    return element;
}

void uasn1_decode_integer(uasn1_item_t *integer,
                          uasn1_buffer_t *buffer,
                          unsigned int length)
{
    unsigned char *in, *out, *out2, c;
    unsigned int i;

    /* Protection against buffer overflow */
    if((buffer->current - buffer->seek) < length)
        length = buffer->current - buffer->seek;

    in = (unsigned char *)(buffer->buffer + buffer->seek);
    buffer->seek += length ;

    integer->value.string.string = (unsigned char*)malloc(length + 1);
    out = (unsigned char *)integer->value.string.string;
    out2 = out;

    if(length == 0) {
        /* Normally illegal */
        out[0] = 0;
    } else {
        c = *(in);
        if(c &0x80) {
            integer->value.string.flags = uasn1_true;
            if((c == 0xFF) && (length != 1)) {
                in ++;
                length --;
            }
            i = length;
            in += i - 1;
            out2 += i - 1;
            while ((!*in) && i) {
                *(out2 --) = 0;
                i --;
                in --;
            }
            if(i == 0) {
                *out = 1;
                out[length] = 0;
                length ++;
            } else {
                *(out2 --) = (*(in --) ^ 0xFF) + 1;
                i --;
                for(;i > 0; i--) {
                    *(out2 --) = *(in --) ^0xFF;
                }
            }
        } else {
            integer->value.string.flags = uasn1_false;
            if((*in == 0) && (length != 1)) {
                in ++;
                length --;
            }
            memcpy(out, in, length);
        }
        integer->value.string.size = length;
    }
}

uasn1_item_t *uasn1_decode(uasn1_buffer_t *buffer)
{
    uasn1_item_t *element = uasn1_decode_tag(buffer);
    unsigned int length = uasn1_decode_length(buffer);

    if((element->tag.type == uasn1_end_of_content) ||
       (element->tag.type == uasn1_null_type)) {
        /* nothing to do */
    } else if(element->tag.type == uasn1_boolean_type) {
        element->value.numeric = uasn1_buffer_get(buffer);
    } else if((element->tag.type == uasn1_integer_type) ||
              (element->tag.type == uasn1_enumerated_type)) {
        uasn1_decode_integer(element, buffer, length);
    } else if(element->tag.type == uasn1_oid_type) {
        uasn1_decode_oid(element, buffer, length);
    } else if((element->tag.type == uasn1_sequence_type) ||
              (element->tag.type == uasn1_set_type)) {
        if(length > 0) {
            unsigned int start = buffer->seek;
            element->value.list.elements = (uasn1_item_t **)
                malloc(16 * sizeof(uasn1_item_t *));
            if(element->value.list.elements) {
                element->value.list.size = 16;
                element->value.list.next = 0;
                while(buffer->seek < (start + length) ) {
                    uasn1_item_t *e = uasn1_decode(buffer);
                    uasn1_add(element, e);
                }
            } else {
                uasn1_free(element);
                element = NULL;
            }
        }
    } else {
        if(element->tag.type == uasn1_bit_string_type) {
            element->value.string.flags = uasn1_buffer_get(buffer);
            length --;
        }

        /* Protection against buffer overflow */
        if((buffer->current - buffer->seek) < length) {
            length = (buffer->current - buffer->seek);
        }
        element->value.string.string = (unsigned char *)malloc(length);
        element->value.string.size = length;
        uasn1_buffer_pop(buffer, element->value.string.string, length);
        if(element->tag.type != uasn1_bit_string_type) {
            element->value.string.flags = 0;
        }
    }
    return element;
}
