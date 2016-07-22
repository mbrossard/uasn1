#include "sasn1.h"

sasn1_t *sasn1_new(size_t size)
{
    sasn1_t *r = malloc(sizeof(sasn1_t));
    sasn1_element_t *e = malloc(size * sizeof(sasn1_element_t));

    if((r != NULL) && (e != NULL)) {
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
    if(value != NULL) {
        free(value->elements);
        free(value);
    }
}

size_t sasn1_allocate(sasn1_t *value)
{
    size_t index = value->count;
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
    uint8_t c, type, tag, _class, val = 0;
    size_t read = 0, r, i, length = 0;
    
    if(ptr == NULL || size == 0) {
        return 0;
    }

    /* Read the first byte */
    c = ptr[0];
    ptr  += 1;
    size -= 1;
    read += 1;
    
    _class = c & uasn1_class_mask;
    val = c & ~(uasn1_class_mask | uasn1_constructed_tag);

    if(_class == uasn1_universal_tag) {
        tag = uasn1_no_tag;
        type = val;
        val = 0;
    }

    /* Allocate an entry and store its index */
    i = sasn1_allocate(value);
    if(index) {
        *index = i;
    }

    value->elements[i].parent        = parent;
    value->elements[i].sibling       = SIZE_MAX;
    value->elements[i].tag.tag       = tag;
    value->elements[i].tag.type      = type;
    value->elements[i].tag.value     = val;
    value->elements[i].tag.flags     = 0;
    value->elements[i].tag._class    = _class;
    value->elements[i].tag.construct = (c & uasn1_constructed_tag) ?
        uasn1_constructed_tag : uasn1_primitive_tag;

    /* Read the length */
    r = sasn1_decode_length(ptr, size, &length);
    ptr  += r;
    size -= r;
    read += r;
    
    if((value->elements[i].tag.type == uasn1_sequence_type) ||
       (value->elements[i].tag.type == uasn1_set_type)) {
        /* This is a sequence or a set */
        while(length > 0) {
            r = sasn1_decode(value, ptr, size, i, NULL);
            ptr  += r;
            read += r;
            size -= r;
            length -= r;
        }
    } else {
        c = 0;
        value->elements[i].ptr   = ptr;
        value->elements[i].size  = length;
        value->elements[i].extra = c;
        read += length;
    }
    
    return read;
}
