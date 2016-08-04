#include "sasn1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

sasn1_t *sasn1_new(size_t size)
{
    sasn1_t *r = malloc(sizeof(sasn1_t));
    sasn1_element_t *e = malloc(size * sizeof(sasn1_element_t));

    if((r != NULL) && (e != NULL)) {
        r->elements = e;
        r->sizes = NULL;
        r->count = 0;
        r->size = size;
    } else {
        free(r);
        free(e);
        r = NULL;
    }
    return r;
}

void sasn1_free(sasn1_t *value)
{
    if(value != NULL) {
        free(value->elements);
        free(value);
    }
}

size_t sasn1_allocate(sasn1_t *value)
{
    size_t index = value->count;

    if(index == value->size) {
        size_t s = value->size * sizeof(sasn1_element_t);
        sasn1_element_t *new = (sasn1_element_t *)malloc(2 * s);
        memcpy(new, value->elements, s);
        free(value->elements);
        value->elements = new;
        value->size *= 2;
    }
    value->count += 1;
    return index;
}

size_t sasn1_decode_length(uint8_t *ptr, size_t size, size_t *length)
{
    size_t rv = 0, read = 0;
    uint8_t c = 0;

    if(ptr == NULL || size == 0) {
        *length = SIZE_MAX;
        return 0;
    }

    c = ptr[0];
    ptr  += 1;
    read += 1;
    size -= 1;

    if(c <= 127) {
        rv = c;
    } else {
        if((c - 128) > sizeof(size_t) || (c - 128) > size) {
            *length = SIZE_MAX;
            return 0;
        }

        size_t i;
        for(i = 0; i < (c - 128); i++) {
            rv = rv << 8;
            rv |= ptr[i];
        }
        read += i;
        size -= i;
    }

    if(length) {
        *length = rv;
    }

    return read;
}

size_t sasn1_decode(sasn1_t *value, uint8_t *ptr, size_t size, size_t parent, size_t *index)
{
    uint8_t c;
    size_t read = 0, r = 0, i, length = 0;
    
    if(ptr == NULL || size == 0) {
        return 0;
    }

    /* Read the first byte */
    c = ptr[read];
    read += 1;

    r = sasn1_decode_length(ptr + read, size - read, &length);
    read += r;

    /* Allocate an entry and store its index */
    i = sasn1_allocate(value);
    if(index) {
        *index = i;
    }

    memset(&(value->elements[i]), 0, sizeof(sasn1_t));

    value->elements[i].parent        = parent;
    value->elements[i].sibling       = SIZE_MAX;
    value->elements[i].tag.tag       = c & ~(uasn1_class_mask | uasn1_constructed_tag);

    value->elements[i].tag.flags     = 0;
    value->elements[i].tag._class    = c & uasn1_class_mask;

    value->elements[i].tag.construct = (c & uasn1_constructed_tag) ?
        uasn1_constructed_tag : uasn1_primitive_tag;

    if(value->elements[i].tag.construct == uasn1_constructed_tag) {
        /* This is a sequence or a set */
        size_t previous = SIZE_MAX, child = SIZE_MAX;
        while(length > 0) {
            r = sasn1_decode(value, ptr + read, size - read, i, &child);
            if(previous != SIZE_MAX && child != SIZE_MAX) {
                value->elements[previous].sibling = child;
                value->elements[i].count++;
            } else {
                value->elements[i].child = child;
                value->elements[i].count = 1;
            }
            previous = child;
            read += r;
            length -= r;
        }
    } else {
        c = 0;
        if((value->elements[i].tag._class == uasn1_universal_tag) &&
           (value->elements[i].tag.tag == uasn1_bit_string_type)) {
            /* In case of bit string, extract the first byte */
            c = ptr[read];
            read   += 1;
            length -= 1;
        }

        value->elements[i].ptr   = ptr + read;
        value->elements[i].size  = length;
        value->elements[i].extra = c;
        read += length;
    }
    
    return read;
}

size_t sasn1_length_length(size_t length)
{
    size_t l = 1;
    if (length >= 0x80) {
        for(l = 2; (length = length >> 8); l++);
    }
    return l;
}

size_t sasn1_encode_length(size_t length, uint8_t *ptr, size_t size)
{
    uint8_t l[sizeof(size_t)];
    int i = 0, j = 0;

    if(length < 0x80) {
        ptr[0] = length;
        i = 1;
    } else {
        do {
            l[j] = (uint8_t)(length & 0xFF);
            length >>= 8;
            j++;
        } while(length);
        /* We have j octets and we set high bit... */
        ptr[i++] = j + 0x80;
        do {
            ptr[i] = l[j - i];
            i++;
        } while(j >= i);
    }
    return i;
}

size_t sasn1_compute_sizes(sasn1_t *value)
{
    size_t index = 0, done = 0;

    if(value->sizes) {
        free(value->sizes);
    }
    value->sizes = calloc(value->count, sizeof(size_t));
    if(!value->sizes) {
        return 0;
    }

    do {
        if((value->elements[index].tag.construct == uasn1_constructed_tag) &&
           (value->sizes[index] == 0)) {
            index = value->elements[index].child;
        } else {
            size_t l = 0;
            if (value->elements[index].tag.construct == uasn1_primitive_tag) {
                value->sizes[index] += value->elements[index].size +
                    (((value->elements[index].tag._class == uasn1_universal_tag) &&
                      (value->elements[index].tag.tag == uasn1_bit_string_type)) ? 1 : 0);
            }

            l += sasn1_length_length(value->sizes[index]) + 1;

            if(index == 0) {
                done = value->sizes[index] + l;
            } else {
                value->sizes[value->elements[index].parent] += value->sizes[index] + l;
                index = (value->elements[index].sibling == SIZE_MAX) ?
                    value->elements[index].parent : value->elements[index].sibling;
            }
        }
    } while (done == 0);

    return done;
}

size_t sasn1_encode(sasn1_t *value, uint8_t *ptr, size_t size)
{
    size_t w = 0, index = 0;

    if(value->sizes == NULL) {
        size_t c = sasn1_compute_sizes(value);
        if(c > size) {
            return SIZE_MAX;
        }
    }
    
    do {
        ptr[w] = (value->elements[index].tag._class
                  | value->elements[index].tag.construct
                  | value->elements[index].tag.tag) & 0xFF;
        w += 1;

        w += sasn1_encode_length(value->sizes[index], ptr + w, size - w);

        if(value->elements[index].tag.construct == uasn1_constructed_tag) {
            index = value->elements[index].child;
        } else {
            if (value->elements[index].tag.tag == uasn1_bit_string_type) {
                ptr[w] = value->elements[index].extra & 0xFF;
                w += 1;
            }

            memcpy(ptr + w, value->elements[index].ptr, value->elements[index].size);
            w += value->elements[index].size;

            while((value->elements[index].sibling == SIZE_MAX) && (index != 0)) {
                index = value->elements[index].parent;
            }

            if(index != 0) {
                index = value->elements[index].sibling;
            }
        }
    } while(index != 0);

    return w;
}
