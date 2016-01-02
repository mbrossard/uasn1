/*
 * Copyright © 2015 Mathias Brossard
 */

#include "uasn1.h"

#include <string.h>
#include <stdio.h>

char *message = "Hello World...";
char *time = "010730154741Z";

unsigned int oid[] = { 2, 5, 4, 3 };
unsigned int oid2[] = { 2, 5, 4632, 34523, 346663 };

int main()
{
    uasn1_buffer_t *buf1 = uasn1_buffer_new(512);
    uasn1_buffer_t *buf2 = uasn1_buffer_new(512);
    uasn1_buffer_t *buf3 = uasn1_buffer_new(512);
    uasn1_item_t *sequence = uasn1_sequence_new(7);
    uasn1_item_t *set = uasn1_set_new(1);
    uasn1_item_t *decoded;

    uasn1_add(set, uasn1_integer_new(0x1F00FF00));
    uasn1_add(sequence, set);
    uasn1_add(sequence, uasn1_boolean_new(uasn1_true));
    uasn1_add(sequence, uasn1_printable_string_new(message, strlen(message)));
    uasn1_add(sequence, uasn1_octet_string_new(message, strlen(message)));
    uasn1_add(sequence, uasn1_bit_string_new(oid, 8, 2));
    uasn1_add(sequence, uasn1_utc_time_new(time, strlen(time)));
    uasn1_add(sequence, uasn1_oid_new(oid, 4));
    uasn1_add(sequence, uasn1_oid_new(oid2, 5));

    uasn1_encode(sequence, buf1);
    uasn1_write_buffer(buf1, "tests/test_asn1.der");

    uasn1_load_buffer(buf2, "tests/test_asn1.der");
    decoded = uasn1_decode(buf2);
    uasn1_encode(decoded, buf3);

    if(buf1->current != buf3->current) {
        fprintf(stderr, "Encoded value differ in size\n");
        return -1;
    }
    if(memcmp(buf1->buffer, buf3->buffer, buf1->current)) {
        fprintf(stderr, "Encoded value differ in content\n");
        return -1;
    }
    
    uasn1_buffer_free(buf1);
    uasn1_buffer_free(buf2);
    uasn1_buffer_free(buf3);
    uasn1_free(sequence);
    uasn1_free(decoded);
    return 0;
}
