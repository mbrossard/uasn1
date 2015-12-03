/*
 * Copyright © 2015 Mathias Brossard
 */

#include <string.h>

#include "uasn1.h"

char *message = "Hello World...";
char *time = "010730154741Z";

unsigned int oid[] = { 2, 5, 4, 3 };
unsigned int oid2[] = { 2, 5, 4632, 34523, 346663 };

int main()
{
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);

    uasn1_item_t *sequence = uasn1_sequence_new(7);
    uasn1_item_t *set = uasn1_set_new(1);

    uasn1_add(set, uasn1_integer_new(0x1F00FF00));
    uasn1_add(sequence, set);
    uasn1_add(sequence, uasn1_boolean_new(uasn1_true));
    uasn1_add(sequence, uasn1_printable_string_new(message, strlen(message)));
    uasn1_add(sequence, uasn1_octet_string_new(message, strlen(message)));
    uasn1_add(sequence, uasn1_bit_string_new(oid, 8, 2));
    uasn1_add(sequence, uasn1_utc_time_new(time, strlen(time)));
    uasn1_add(sequence, uasn1_oid_new(oid, 4));
    uasn1_add(sequence, uasn1_oid_new(oid2, 5));

    uasn1_encode(sequence, buffer);
    uasn1_write_buffer(buffer, "test.der");

    uasn1_free(sequence);
    uasn1_buffer_free(buffer);
    return 0;
}
