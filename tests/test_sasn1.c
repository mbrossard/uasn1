/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "sasn1.h"

#include <string.h>
#include <stdio.h>

int main()
{
    char *path = "tests/ocsp_rsa1_crt.der";
    uint8_t input[1024 * 64];
    size_t l = 0, r;
    FILE *f = fopen(path, "rb");
    if(f) {
        l = fread(input, 1, sizeof(input), f);
        fclose(f);
    }
    fprintf(stderr, "Loaded %zu bytes\n", l);
    sasn1_t *v = sasn1_new(16);
    r = sasn1_decode(v, input, l, SIZE_MAX, NULL);
    fprintf(stderr, "Parsed %zu bytes\n", r);
    return 0;
}
