#ifndef SASN1_H
#define SASN1_H

#include <stdlib.h>
#include <stdint.h>

#include "uasn1.h"

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

typedef struct {
    uasn1_type_t type;
    uasn1_construct_t construct;
    uasn1_class_t _class;
    uasn1_tagging_class_t tag;
    uasn1_flags_t flags;
    uint8_t value;
} sasn1_tag_t;

typedef struct {
    size_t parent;
    size_t sibling;
    union {
        struct {
            size_t child;
            size_t count;
        };
        struct {
            uint8_t *ptr;
            size_t size;
            uint8_t extra;
        };
    };
    sasn1_tag_t tag;
} sasn1_element_t;

typedef struct {
    sasn1_element_t *elements;
    size_t count;
    size_t size;
} sasn1_t;

sasn1_t *sasn1_new(size_t size);
void sasn1_free(sasn1_t *value);
size_t sasn1_allocate(sasn1_t *value);
size_t sasn1_decode_length(uint8_t *ptr, size_t size, size_t *length);
size_t sasn1_decode(sasn1_t *value, uint8_t *ptr, size_t size, size_t parent, size_t *index);

#endif
