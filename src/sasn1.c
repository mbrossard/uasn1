#include "sasn1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

sasn1_t *sasn1_new(size_t size)
{
    sasn1_t *r = malloc(sizeof(sasn1_t));
    sasn1_element_t *e;

    if(size < 16) {
        size = 16;
    }
    e = calloc(size, sizeof(sasn1_element_t));

    /* Check both allocations succeeded */
    if ((r != NULL) && (e != NULL)) {
        r->elements = e;
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
    if (value != NULL) {
        free(value->elements);
        free(value);
    }
}

size_t sasn1_allocate(sasn1_t *value)
{
    size_t index = value->count;

    if ((value == NULL) || (value->elements == NULL)) {
        return SIZE_MAX;
    }

    /* Check if the buffer is full */
    if (index == value->size) {
        /* Re-allocate a buffer with double the size */
        size_t s = value->size * sizeof(sasn1_element_t);
        sasn1_element_t *new = (sasn1_element_t *)malloc(2 * s);

        if (new == NULL) {
            return SIZE_MAX;
        }

        /* Copy existing values */
        memcpy(new, value->elements, s);
        /* Fill the rest with zeros */
        memset(((char *)new) + s, 0, s);
        /* Free older array */
        free(value->elements);
        /* Update */
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

    if (ptr == NULL || size == 0) {
        return SIZE_MAX;
    }

    /* Read the first byte */
    c = ptr[read];
    read += 1;

    if (c <= 127) {
        /* Small length case */
        rv = c;
    } else {
        /* Long length case: l is the number of bytes to encode length */
        size_t i, l = c - 128;

        if (l > sizeof(size_t) || (size < (read + l))) {
            return SIZE_MAX;
        }

        /* Load big endian number of l bytes */
        for (i = 0; i < l; i++) {
            rv <<= 8;
            rv |= ptr[read + i];
        }
        read += l;
    }

    if (length) {
        *length = rv;
    }

    return read;
}

size_t sasn1_decode(sasn1_t *value, uint8_t *ptr, size_t size, size_t parent, size_t *index)
{
    uint8_t c;
    size_t read = 0, r = 0, i, length = 0;
    
    if (ptr == NULL || size == 0) {
        return SIZE_MAX;
    }

    /* Read the first byte */
    c = ptr[read];
    read += 1;

    /* Allocate an entry and store its index */
    i = sasn1_allocate(value);
    if (i == SIZE_MAX) {
        return SIZE_MAX;
    }
    if (index) {
        *index = i;
    }

    memset(&(value->elements[i]), 0, sizeof(sasn1_t));

    value->elements[i].parent    = parent;
    value->elements[i].sibling   = SIZE_MAX;
    value->elements[i].flags     = 0;
    value->elements[i]._class    = c & uasn1_class_mask;
    value->elements[i].construct = (c & uasn1_constructed_tag) ?
        uasn1_constructed_tag : uasn1_primitive_tag;
    value->elements[i].tag       = c & ~(uasn1_class_mask | uasn1_constructed_tag);

    if (value->elements[i].tag == 31) {
        /*
          Special case for large value tags: they are encoded in
          chunks of 7 bits using a MSB set to 0 as a terminator. We
          try to support all values that would fit into size_t.
        */
        uint8_t j = 0, k = (sizeof(size_t) * 8) / 7;
        uint8_t m = 1 << (sizeof(size_t) * 8) % 7;
        r = 0;
        do {
            if (size < (read + 1)) {
                return SIZE_MAX;
            }

            /* Read one byte */
            c = ptr[read];
            read += 1;

            /* Concatenate the last 7 bits */
            r <<= 7;
            r |= c & 0x7F;

            /* Special case if the first byte value is small enough */
            if ((j == 0) && ((c & 0x7F) < m)) {
                k += 1;
            }
            j++;
            if (j > k) {
                /* The tag value is too big to fit */
                return SIZE_MAX;
            }
        } while(c & 0x80);
        value->elements[i].tag = r;
    }

    if (size < (read + 1)) {
        return SIZE_MAX;
    }

    if (ptr[read] == 0x80) {
        /* This is a BER indefinite length encoding  */
        size_t previous = SIZE_MAX, child = SIZE_MAX;

        read += 1;
        value->elements[i].child = child;
        value->elements[i].count = 0;
        value->elements[i].flags = uasn1_indefinite_type;

        /* Check there is at least enough bytes for end marker */
        if (size < (read + 2)) {
            return SIZE_MAX;
        }

        /* The end marker is two consecutive 0x0 bytes */
        while (!((ptr[read] == 0x0) && (ptr[read + 1] == 0x0))) {
            r = sasn1_decode(value, ptr + read, size - read, i, &child);
            if ((r == SIZE_MAX) || (size < (read + r))) {
                return SIZE_MAX;
            }
            read += r;

            if (previous != SIZE_MAX && child != SIZE_MAX) {
                value->elements[previous].sibling = child;
                value->elements[i].count++;
            } else {
                value->elements[i].child = child;
                value->elements[i].count = 1;
            }
            previous = child;

            if (size < (read + 2)) {
                return SIZE_MAX;
            }
        }
        /* Increment for end marker */
        read += 2;
    } else if (value->elements[i].construct == uasn1_constructed_tag) {
        /* This is a sequence or a set */
        size_t previous = SIZE_MAX, child = SIZE_MAX;
        value->elements[i].child = child;
        value->elements[i].count = 0;

        r = sasn1_decode_length(ptr + read, size - read, &length);
        if ((r == SIZE_MAX) || (size < (read + r + length))) {
            return SIZE_MAX;
        }
        read += r;

        while (length > 0) {
            if (read >= size) {
                return SIZE_MAX;
            }

            r = sasn1_decode(value, ptr + read, size - read, i, &child);
            if (r == SIZE_MAX) {
                return SIZE_MAX;
            }
            read += r;
            length -= r;

            if (previous != SIZE_MAX && child != SIZE_MAX) {
                value->elements[previous].sibling = child;
                value->elements[i].count++;
            } else {
                value->elements[i].child = child;
                value->elements[i].count = 1;
            }
            previous = child;
        }
    } else {
        r = sasn1_decode_length(ptr + read, size - read, &length);
        if ((r == SIZE_MAX) || (size < (read + r + length))) {
            return SIZE_MAX;
        }
        read += r;

        c = 0;
        if ((value->elements[i]._class == uasn1_universal_tag) &&
            (value->elements[i].tag == uasn1_bit_string_type)) {
            if(length == 0) {
                return SIZE_MAX;
            }
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
        for (l = 2; (length = length >> 8); l++);
    }
    return l;
}

size_t sasn1_encode_length(size_t length, uint8_t *ptr, size_t size)
{
    uint8_t l[sizeof(size_t)];
    int i = 0, j = 0;

    if (size < 1) {
        return SIZE_MAX;
    }

    if (length < 0x80) {
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

size_t sasn1_tag_size(size_t v)
{
    size_t r = 1;

    if (v >= 31) {
        do {
            v >>= 7;
            r += 1;
        } while (v);
    }

    return r;
}

size_t sasn1_compute_sizes(sasn1_t *value)
{
    size_t index = 0, done = 0;

    do {
        if (((value->elements[index].construct == uasn1_constructed_tag) ||
             (value->elements[index].flags == uasn1_indefinite_type)) &&
            (value->elements[index].child != SIZE_MAX) &&
            (value->elements[index].length == 0)) {
            index = value->elements[index].child;
        } else {
            size_t l = 0;
            if (value->elements[index].construct == uasn1_primitive_tag) {
                value->elements[index].length += value->elements[index].size +
                    (((value->elements[index]._class == uasn1_universal_tag) &&
                      (value->elements[index].tag == uasn1_bit_string_type)) ? 1 : 0);
            }

            if (value->elements[index].flags == uasn1_indefinite_type) {
                l = sasn1_tag_size(value->elements[index].tag) + 3;
            } else {
                l = sasn1_length_length(value->elements[index].length);
                if (l == SIZE_MAX) {
                    return SIZE_MAX;
                }
                l += sasn1_tag_size(value->elements[index].tag);
            }

            if (index == 0) {
                done = value->elements[index].length + l;
            } else {
                value->elements[value->elements[index].parent].length += value->elements[index].length + l;
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

    if (value->elements[0].length == 0) {
        size_t c = sasn1_compute_sizes(value);
        if ((c == SIZE_MAX) || (c > size)) {
            return SIZE_MAX;
        }
    }

    do {
        if (value->elements[index].tag < 31) {
            if (size < w + 1) {
                return SIZE_MAX;
            }
            ptr[w] = (value->elements[index]._class
                      | value->elements[index].construct
                      | value->elements[index].tag) & 0xFF;
            w += 1;
        } else {
            uint8_t i = 0, j, max = (sizeof(size_t) / 7 + 1) * 8;
            uint8_t buffer[max];
            size_t t = value->elements[index].tag;

            do {
                buffer[i] = t & 0x7F;
                i += 1;
                t >>= 7;
            } while(t);

            if (size < (w + i + 1)) {
                return SIZE_MAX;
            }

            ptr[w] = (value->elements[index]._class
                      | value->elements[index].construct
                      | 31) & 0xFF;
            w += 1;

            for (j = 0; j <= i; j++) {
                ptr[w] = (((i == j) ? 0x0 : 0x80) | buffer[i - j]) & 0xFF;
                w += 1;             
            }
        }

        if (value->elements[index].flags == uasn1_indefinite_type) {
            if (size < w + 3) {
                return SIZE_MAX;
            }
            ptr[w] = 0x80;
            w += 1;
        } else {
            size_t r = sasn1_encode_length(value->elements[index].length, ptr + w, size - w);
            if (r == SIZE_MAX) {
                return SIZE_MAX;
            }
            w += r;
        }

        if (((value->elements[index].construct == uasn1_constructed_tag) ||
             (value->elements[index].flags == uasn1_indefinite_type)) &&
            (value->elements[index].child != SIZE_MAX)) {
            index = value->elements[index].child;
        } else {
            if ((value->elements[index]._class == uasn1_universal_tag) &&
                (value->elements[index].tag == uasn1_bit_string_type)) {
                if (size < (w + 1)) {
                    return SIZE_MAX;
                }
                ptr[w] = value->elements[index].extra & 0xFF;
                w += 1;
            }

            if (value->elements[index].construct == uasn1_primitive_tag) {
                if (size < (w + value->elements[index].size)) {
                    return SIZE_MAX;
                }
                memcpy(ptr + w, value->elements[index].ptr, value->elements[index].size);
                w += value->elements[index].size;
            }

            while ((value->elements[index].sibling == SIZE_MAX) && (index != 0)) {
                index = value->elements[index].parent;
                if (value->elements[index].flags == uasn1_indefinite_type) {
                    if (size < (w + 2)) {
                        return SIZE_MAX;
                    }
                    ptr[w] = 0x0;
                    ptr[w + 1] = 0x0;
                    w += 2;
                }
            }

            if (index != 0) {
                index = value->elements[index].sibling;
            }
        }
    } while (index != 0);

    return w;
}
