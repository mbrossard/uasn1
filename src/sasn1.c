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
