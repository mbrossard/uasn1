/*
 * Copyright © 2015 Mathias Brossard
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "uasn1.h"

uasn1_item_t *uasn1_item_new(uasn1_type_t type)
{
    uasn1_item_t *element = (uasn1_item_t *)malloc(sizeof(uasn1_item_t));
    if(element) {
        element->tag.type      = type;
        element->tag.construct = uasn1_primitive_tag;
        element->tag._class    = uasn1_universal_tag;
        element->tag.tag       = uasn1_no_tag;
        element->tag.value     = 0;
        element->tag.flags     = 0;
    }
    return element;
}

uasn1_item_t *uasn1_string_new(uasn1_type_t type, void *string,
                               size_t size)
{
    uasn1_item_t *element = uasn1_item_new(type);
    if(element) {
        element->value.string.string = (unsigned char *)malloc(size);
        if(element->value.string.string) {
            /* Check for consistence here */
            memcpy(element->value.string.string, string, size);
            element->value.string.size = size;
            element->value.string.flags = 0;
        } else {
            free(element);
            element = NULL;
        }
    }
    return element;
}

uasn1_item_t *uasn1_large_integer_new(uasn1_type_t type, void *string,
                                      size_t size)
{
    uasn1_item_t *element = uasn1_item_new(type);
    if(element) {
        /* Do we need to add a leading zero */
        int lead = ((char *)string)[0] & 0x80 ? 1 : 0;
        element->value.string.string = (unsigned char *)malloc(size + lead);
        if(element->value.string.string) {
            /* Check for consistence here */
            element->value.string.string[0] = 0;
            memcpy(element->value.string.string + lead, string, size);
            element->value.string.size = size + lead;
            element->value.string.flags = 0;
        } else {
            free(element);
            element = NULL;
        }
    }
    return element;
}

uasn1_item_t *uasn1_oid_new(unsigned int *elements,
                            size_t size)
{
    uasn1_item_t *element = uasn1_item_new(uasn1_oid_type);
    if(element) { /* Malloc failure will be caught earlier if check fails */
        element->value.oid.elements = (unsigned int *) malloc(size * sizeof(unsigned int));
        if(element->value.oid.elements) {
            unsigned int i;
            for(i = 0; i < size; i++) {
                element->value.oid.elements[i] = elements[i];
            }
            element->value.oid.size = size;
        } else {
            free(element);
            element = NULL;
        }
    }
    return element;
}

uasn1_item_t *uasn1_natural_new(uasn1_type_t type, int i)
{
    int neg = 0, a = 0, b;
    uasn1_item_t *integer;

    if(i < 0) {
        neg = 1;
        i = -i;
    }

    if(i == 0) {
        a = 1;
    } else {
        for(b = i; (b != 0); b = b >> 8, a++) { /* Empty */ }
    }

    integer = uasn1_item_new(type);

    if(integer) {
        integer->value.string.flags = 0;
        integer->value.string.size = a;
        integer->value.string.string = (unsigned char *)
            malloc(a * sizeof(unsigned char));
        if(integer->value.string.string == NULL) {
            free(integer);
            integer = NULL;
        } else {
            integer->value.string.flags = neg;
            for(b = 0; b < a; b++) {
                integer->value.string.string[a - 1 - b] = (i >>  8 * b ) & 0xFF;
            }
        }
    }
    return integer;
}

int uasn1_add(uasn1_item_t *list, uasn1_item_t *element)
{
    if((list != NULL) && (element != NULL)) {
        if(list->value.list.next == list->value.list.size) {
#ifndef USE_REALLOC
            uasn1_item_t **temp = (uasn1_item_t **) malloc
                (list->value.list.size * 2 * sizeof(uasn1_item_t *));
            if(temp) {
                memcpy(temp, list->value.list.elements,
                       list->value.list.size * sizeof(uasn1_item_t *));
            }
            free(list->value.list.elements);
            list->value.list.elements = temp;
#else
            list->value.list.elements =  (uasn1_item_t **) realloc
                ((void *)list->value.list.elements,
                 list->value.list.size * 2 * sizeof(uasn1_item_t *));
#endif
            list->value.list.size *= 2;
        }
        if((list->value.list.elements)) {
            list->value.list.elements[list->value.list.next] = element;
            ++list->value.list.next;
            return 0;
        }
    }
    return -1;
}

uasn1_item_t *uasn1_array_new(uasn1_type_t type, size_t size)
{
    uasn1_item_t *element = uasn1_item_new(type);
    if(element) {
        element->tag.construct = uasn1_constructed_tag;
        if(size < 2) {
            size = 2;
        }
        element->value.list.elements = (uasn1_item_t **)
            malloc(size * sizeof(uasn1_item_t *));

        if(element->value.list.elements) {
            element->value.list.size = size;
            element->value.list.next = 0;
        } else {
            uasn1_free(element);
            element = NULL;
        }
    }
    return element;
}

void uasn1_free(uasn1_item_t *element)
{
    if(element) {
        if((element->tag.type == uasn1_end_of_content) ||
           (element->tag.type == uasn1_null_type) ||
           (element->tag.type == uasn1_boolean_type)) {
            /* nada */
        } else if(element->tag.type == uasn1_oid_type) {
            free(element->value.oid.elements);
        } else if((element->tag.type == uasn1_sequence_type) ||
                  (element->tag.type == uasn1_set_type)) {
            unsigned int i, j = uasn1_count(element);
            for(i = 0; i < j; i++) {
                uasn1_free(uasn1_get(element, i));
            }
            free(element->value.list.elements);
        } else {
            free(element->value.string.string);
        }
        free(element);
    }
}

uasn1_item_t *uasn1_preencoded(uasn1_buffer_t *buffer)
{
    uasn1_item_t *element = uasn1_octet_string_new(buffer->buffer, buffer->current);
    if(element) {
        element->tag.flags = uasn1_preencoded_type;
    }
    return element;
}

uasn1_buffer_t *uasn1_buffer_new(size_t size)
{
    uasn1_buffer_t *buffer;
    buffer = (uasn1_buffer_t *)malloc(sizeof(uasn1_buffer_t));
    if(buffer) {
        buffer->buffer = (unsigned char *)malloc(size);
        if(buffer->buffer) {
            buffer->size = size;
            buffer->current = 0;
            buffer->seek = 0;
        } else {
            free(buffer);
            buffer = NULL;
        }
    }
    return buffer;
}

void uasn1_buffer_free(uasn1_buffer_t *buffer)
{
    if(buffer) {
        free(buffer->buffer);
    }
    free(buffer);
}


int uasn1_buffer_reserve(uasn1_buffer_t *buffer, size_t size)
{
    unsigned int s;
    for(s = buffer->size; (s - buffer->current) <= size; s = 2 * s) { /* empty */};
    if(s != buffer->size) {
#ifndef USE_REALLOC
        unsigned char *temp = (unsigned char *) malloc(s);
        if(temp) {
            memcpy(temp, buffer->buffer, buffer->size);
        }
        free(buffer->buffer);
        buffer->buffer = temp;
#else
        buffer->buffer = (unsigned char *) realloc((void *)(buffer->buffer), s);
#endif
        buffer->size = s;
    }
    return (buffer->buffer == NULL) ? -1 : 0;
}

int uasn1_buffer_push(uasn1_buffer_t *buffer, void* ptr, size_t size)
{
    int rv = 0;
    if(buffer->current + size > buffer->size) {
        rv = uasn1_buffer_reserve(buffer, size);
    }
    if(rv == 0) {
        memcpy(buffer->buffer + buffer->current, ptr, size);
        buffer->current = buffer->current + size;
    }
    return rv;
}

int uasn1_buffer_put(uasn1_buffer_t *buffer, unsigned char c)
{
    int rv = 0;
    if(buffer->current + 1 > buffer->size) {
        rv = uasn1_buffer_reserve(buffer, 1);
    }
    if(rv == 0) {
        buffer->buffer[buffer->current] = c;
        buffer->current++;
    }
    return rv;   
}

unsigned char uasn1_buffer_get(uasn1_buffer_t *buf)
{
    return (buf->seek < buf->current) ? buf->buffer[buf->seek++] : 0;
}

int uasn1_buffer_pop(uasn1_buffer_t *buffer, void *ptr, size_t size)
{
    int rv = -1;

    if(buffer && ptr) {
        /* Protection against buffer overflow */
        if(size > (buffer->current - buffer->seek)) {
            size = buffer->current - buffer->seek;
        }

        memcpy(ptr, buffer->buffer + buffer->seek, size);
        buffer->seek += size;
        rv = size;
    }
    return rv;
}

int uasn1_write_buffer(uasn1_buffer_t *buffer, char *filename)
{
    FILE *f = fopen(filename, "w");
    unsigned int r = fwrite(buffer->buffer, 1, buffer->current, f);
    fclose(f);
    return ((r == buffer->current) ? 0 : -1);
}

int uasn1_load_buffer(uasn1_buffer_t *buffer, char *filename)
{
    FILE *f = fopen(filename, "r");
    unsigned int rsize = 16384;
    unsigned int bread = 0;
    int rv = -1;

    if(f) {
        do {
            uasn1_buffer_reserve(buffer, rsize);
            buffer->current += bread;
        } while((bread = fread(buffer->buffer, 1, rsize, f)) == rsize);
        buffer->current += bread;

        fclose(f);
        rv = 0;
    }
    return rv;
}
