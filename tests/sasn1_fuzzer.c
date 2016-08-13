/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "sasn1.h"

#include <string.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    uint8_t input[1024 * 64];
    uint8_t output[1024 * 64];
    size_t l, r;

    if(argc != 2) {
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if(f) {
        l = fread(input, 1, sizeof(input), f);
        fprintf(stderr, "Loaded '%s'\n", argv[1]);
        fclose(f);
    } else {
        fprintf(stderr, "Error opening '%s'\n", argv[1]);
        return 1;
    }
    sasn1_t *v = sasn1_new(16);
    r = sasn1_decode(v, input, l, SIZE_MAX, NULL);
    if(l != r) {
        fprintf(stderr, "Decoding: sizes do not match got %zu expected %zu\n", r, l);
        return 1;
    }
    r = sasn1_compute_sizes(v);
    if(l != r) {
        fprintf(stderr, "Computing: sizes do not match got %zu expected %zu\n", r, l);
        return 1;
    }
    
    r = sasn1_encode(v, output, sizeof(output));
    if(l != r) {
        fprintf(stderr, "Encoding: sizes do not match got %zu expected %zu\n", r, l);
        return 1;
    }
    
    if(memcmp(input, output, l) != 0) {
        fprintf(stderr, "Re-encoding does not match original\n");
        return 1;
    }
        
    sasn1_free(v);

    fprintf(stderr, "Test successful\n");
    return 0;
}
