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
    size_t read = 0;
    return read;
}
