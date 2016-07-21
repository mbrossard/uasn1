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
    union {
        struct {
            uint32_t child;
            uint32_t count;
        };
        struct {
            void *ptr;
            uint32_t size;
        };
    };
    sasn1_tag_t tag;
} sasn1_element_t;

typedef struct {
    sasn1_element_t *elements;
    uint32_t count;
    uint32_t size;
} sasn1_t;

#endif
