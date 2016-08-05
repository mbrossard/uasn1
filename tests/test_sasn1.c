/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "sasn1.h"

#include <string.h>
#include <stdio.h>

int main()
{
    char *paths[] = {
        "tests/ec_ca.der",
        "tests/ec_ca_crl.der",
        "tests/ec_csr.der",
        "tests/ec_tsa_req.der",
        "tests/ec_tsa_res.der",
        "tests/ocsp_rsa1_crt.der",
        "tests/ocsp_rsa1_crt_req.der",
        "tests/ocsp_rsa1_crt_res.der",
        "tests/ocsp_rsa2_crt.der",
        "tests/ocsp_rsa2_crt_req.der",
        "tests/ocsp_rsa2_crt_res.der",
        "tests/rsa1_ca.der",
        "tests/rsa1_ca_crl.der",
        "tests/rsa1_csr.der",
        "tests/rsa1_tsa_req.der",
        "tests/rsa1_tsa_res.der",
        "tests/rsa2_ca.der",
        "tests/rsa2_ca_crl.der",
        "tests/rsa2_csr.der",
        "tests/rsa2_tsa_req.der",
        "tests/rsa2_tsa_res.der",
        "tests/tsa_rsa1_crt.der",
        "tests/tsa_rsa2_crt.der"
    };
    uint8_t input[1024 * 64];
    uint8_t output[1024 * 64];
    size_t err = 0, i, l, r;

    for(i = 0; i < (sizeof(paths)/sizeof(char *)); i++) {
        FILE *f = fopen(paths[i], "rb");
        if(f) {
            l = fread(input, 1, sizeof(input), f);
            fprintf(stderr, "Loaded '%s'\n", paths[i]);
            fclose(f);
        } else {
            fprintf(stderr, "Error opening '%s'\n", paths[i]);
            return 1;
        }
        sasn1_t *v = sasn1_new(16);
        r = sasn1_decode(v, input, l, SIZE_MAX, NULL);
        if(l != r) {
            fprintf(stderr, "Decoding: sizes do not match got %zu expected %zu\n", r, l);
            err = 1;
        }
        r = sasn1_compute_sizes(v);
        if(l != r) {
            fprintf(stderr, "Computing: sizes do not match got %zu expected %zu\n", r, l);
            err = 1;
        }
    
        r = sasn1_encode(v, output, sizeof(output));
        if(l != r) {
            fprintf(stderr, "Encoding: sizes do not match got %zu expected %zu\n", r, l);
            err = 1;
        }
    
        if(memcmp(input, output, l) != 0) {
            fprintf(stderr, "Re-encoding does not match original\n");
            err = 1;
            return err;
        }
        
        sasn1_free(v);
    }
    return err;
}
