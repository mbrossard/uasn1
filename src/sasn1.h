#ifndef SASN1_H
#define SASN1_H

#include <stdlib.h>

#include "uasn1.h"

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

typedef struct {
    uasn1_type_t type;
    uasn1_construct_t construct;
    uasn1_class_t _class;
    uasn1_tagging_class_t tag;
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
            void *ptr;
            size_t size;
        };
    };
    sasn1_tag_t tag;
} sasn1_element_t;

typedef struct {
    sasn1_element_t *elements;
    size_t count;
    size_t size;
} sasn1_t;

#endif
