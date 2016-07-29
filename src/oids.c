/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "oids.h"

#include <stdlib.h>
#include <string.h>

static uasn1_item_t *uasn1_decode_oid(uasn1_item_t *element,
                                      uasn1_buffer_t *buffer,
                                      unsigned int length)
{
    unsigned int i, j = 1;
    unsigned int *v;
    unsigned char c;

    /* Protection against buffer overflow */
    if((buffer->current - buffer->seek) < length) {
        length = buffer->current - buffer->seek;
    }

    /* How many elements ? */
    for(i = 0; i < length; i++) {
        if((buffer->buffer[i + buffer->seek] < 0x80)) j++;
    }

    v = (unsigned int *) malloc((j) * sizeof(unsigned int));
    i = 1;
    do {
        c = uasn1_buffer_get(buffer);
        if(i == 1) {
            v[0] = c / 40;
            v[1] = c % 40;
        } else {
            v[i] = (v[i] << 7) | (c & 0x7F);
        }

        if (c < 0x80) {
            i++;
            if(i < j) {
                v[i] = 0;
            }
        }
    } while(i < j);
    element->value.oid.elements = v;
    element->value.oid.size = j;
    return element;
}

uasn1_item_t *uasn1_get_oid_by_name(char *name)
{
  uasn1_item_t *ret;
  uasn1_buffer_t *buffer;
  unsigned int i;

  for(i = 0; oidtable[i].name != NULL; i++)
	{
	  if(strcmp(name, oidtable[i].name) == 0)
		{
		  ret = uasn1_item_new(uasn1_oid_type);
		  buffer = uasn1_buffer_new(oidtable[i].size);
		  uasn1_buffer_push(buffer, oidtable[i].oid, oidtable[i].size);
		  uasn1_decode_oid(ret, buffer, oidtable[i].size);
		  uasn1_buffer_free(buffer);
		  return ret;
		}
	}
  return NULL;
}

char *uasn1_get_oid(uasn1_item_t *oid)
{
    char *name = NULL;
    uasn1_buffer_t *buffer = uasn1_buffer_new(16);
    unsigned int i, j;

    uasn1_encode(oid, buffer);

    for(i = 0; oidtable[i].name != NULL; i++) {
        if(oidtable[i].size == buffer->current - 2) {
            int diff = 0;
            for (j = 0; ((j < oidtable[i].size) && (diff == 0)) ; j++) {
                if((buffer->buffer[j + 2]) != (oidtable[i].oid[j])) {
                    diff = 1;
                }
            }
            if(diff == 0) {
                j = strlen(oidtable[i].name) + 1;
                name = (char *)malloc(j);
                memcpy(name, oidtable[i].name, j);
                goto end;
			}
		}
	}

 end:
    uasn1_buffer_free(buffer);
    return name;
}
