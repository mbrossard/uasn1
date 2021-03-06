#ifndef SASN1_H
#define SASN1_H

#include <stdlib.h>
#include <stdint.h>

#include "uasn1.h"

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

typedef struct {
    /**
     * Index of parent element
     */
    size_t parent;
    /**
     * Index of next element
     */
    size_t sibling;
    /**
     * Length in bytes of encoded subtree
     */
    size_t length;
    union {
        /**
         * In case of constructed element
         */
        struct {
            /**
             * Index of first sub-element
             */
            size_t child;
            /**
             * Count of sub-elements
             */
            size_t count;
        };
        /**
         * In case of scalar element
         */
        struct {
            /**
             * Pointer to content
             */
            uint8_t *ptr;
            /**
             * Size of data
             */
            size_t size;
        };
    };
    uint32_t tag;
    uint8_t construct;
    uint8_t _class;
    uint8_t flags;
    uint8_t extra;
} sasn1_element_t;

/**
 * Top-level structure
 */
typedef struct {
    /**
     * Buffer containing ASN.1 elements
     */
    sasn1_element_t *elements;
    /**
     * Count of elements used
     */
    size_t count;
    /**
     * Size of allocated buffer (in number of elements)
     */
    size_t size;
} sasn1_t;

/**
 * @brief Allocate sasn1_t structure
 * @param [in] size Initial size of buffer
 * @return pointer to sasn1_t structure
 * @return NULL in case of failure
 */
sasn1_t *sasn1_new(size_t size);

/**
 * @brief Free sasn1_t structure
 * @param [in] value pointer to sasn1_t structure
 */
void sasn1_free(sasn1_t *value);

/**
 * @brief Allocate an entry in sasn1_t structure
 * @param [in] value pointer to sasn1_t structure
 * @return index of allocated entry
 * @return @c SIZE_MAX otherwise
 */
size_t sasn1_allocate(sasn1_t *value);

/**
 * @brief Decode length ASN.1 element length
 * @param [in] ptr value pointer to data
 * @param [in] size maximum length of data to parse
 * @param [out] length pointer to store length
 * @return number of bytes read
 * @return @c SIZE_MAX otherwise
 */
size_t sasn1_decode_length(uint8_t *ptr, size_t size, size_t *length);

/**
 * @brief Decode ASN.1 structure
 * @param [out] value pointer to sasn1_t structure
 * @param [in] ptr value pointer to data
 * @param [in] size maximum length of data to parse
 * @param [in] parent index of parent entry
 * @param [out] index pointer to store index of decoded element
 * @return number of bytes read
 * @return @c SIZE_MAX in case of error
 */
size_t sasn1_decode(sasn1_t *value, uint8_t *ptr, size_t size,
                    size_t parent, size_t *index);

/**
 * @brief Compute the size of the elements in sasn1_t structure
 * @param [in] value pointer to sasn1_t structure
 * @return total size of the encoding of value will occupy
 * @return @c SIZE_MAX in case of error
 */
size_t sasn1_compute_sizes(sasn1_t *value);

/**
 * @brief Encode ASN.1 structure to buffer
 * @param [in] value pointer to sasn1_t structure
 * @param [out] ptr value pointer to buffer
 * @param [in] size buffer length
 * @return number of bytes written
 * @return @c SIZE_MAX in case of error
 */
size_t sasn1_encode(sasn1_t *value, uint8_t *ptr, size_t size);

#endif
