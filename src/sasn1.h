#ifndef SASN1_H
#define SASN1_H

#include <stdlib.h>
#include <stdint.h>

#include "uasn1.h"

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

typedef struct {
    size_t parent;
    size_t sibling;
    size_t length;
    union {
        struct {
            size_t child;
            size_t count;
        };
        struct {
            uint8_t *ptr;
            size_t size;
        };
    };
    uint32_t tag;
    uint8_t construct;
    uint8_t _class;
    uint8_t flags;
    uint8_t extra;
} sasn1_element_t;

typedef struct {
    sasn1_element_t *elements;
    size_t count;
    size_t size;
} sasn1_t;

/**
 * @brief Allocate sasn1_t structure
 * @param [in] size Initial size of buffer
 * @return pointer to sasn1_t structure
 * @return NULL in case of failure
 */
sasn1_t *sasn1_new(size_t size);
void sasn1_free(sasn1_t *value);
size_t sasn1_allocate(sasn1_t *value);
size_t sasn1_decode_length(uint8_t *ptr, size_t size, size_t *length);
size_t sasn1_decode(sasn1_t *value, uint8_t *ptr, size_t size, size_t parent, size_t *index);
size_t sasn1_compute_sizes(sasn1_t *value);
size_t sasn1_encode(sasn1_t *value, uint8_t *ptr, size_t size);

#endif
