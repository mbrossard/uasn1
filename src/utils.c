/*
 * Copyright © 2015 Mathias Brossard
 */

#include "utils.h"

#include <time.h>

int uasn1_write_encoded(uasn1_item_t *element, char *filename)
{
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);

    uasn1_encode(element, buffer);
    uasn1_write_buffer(buffer, filename);
    uasn1_buffer_free(buffer);
    return 0;
}

uasn1_item_t *uasn1_get_generalized_time()
{
    unsigned char g[16];
    struct tm st;
    time_t t = time(NULL);

    gmtime_r(&t, &st);

    sprintf((char *)g, "%04d%02d%02d%02d%02d%02dZ",
            (st.tm_year + 1900) % 10000,
            st.tm_mon % 100,
            st.tm_mday % 100,
            st.tm_hour % 100,
            st.tm_min % 100,
            st.tm_sec % 100);

    return uasn1_generalized_time_new(g, 15);
}

uasn1_item_t *uasn1_get_utc_time()
{
    unsigned char g[16];
    struct tm st;
    time_t t = time(NULL);

    gmtime_r(&t, &st);

    sprintf((char *)g, "%02d%02d%02d%02d%02d%02dZ",
            st.tm_year % 100,
            st.tm_mon + 1 % 100,
            st.tm_mday % 100,
            st.tm_hour % 100,
            st.tm_min % 100,
            st.tm_sec % 100);

    return uasn1_utc_time_new(g, 13);
}

#ifdef HAVE_OPENSSL

#include <openssl/bio.h>
#include <openssl/evp.h>

int uasn1_write_base64_buffer(uasn1_buffer_t *buffer, FILE *f)
{
    BIO *bio, *b64;
    int rv = -1;
    unsigned int written;
    if(f) {
        bio = BIO_new_fp(f, BIO_NOCLOSE);
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        written = BIO_write(bio, buffer->buffer, buffer->current);
        if(written == buffer->current) {
            rv = 0;
        }
        rv = BIO_flush(bio);
        BIO_free_all(bio);
    }
    return rv;
}

int uasn1_buffer_dumpBase64(uasn1_buffer_t *buffer, char *filename)
{
    BIO *bio, *b64;
    unsigned char inbuf[512];
    int inlen;
    int rv = -1;
    FILE *f = fopen(filename, "r");

    if(f != NULL) {
        rv = 0;
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_fp(f, BIO_NOCLOSE);
        bio = BIO_push(b64, bio);
        while((inlen = BIO_read(bio, inbuf, sizeof(inbuf))) > 0) {
            uasn1_buffer_push(buffer, inbuf, inlen);
        }
        BIO_free_all(bio);
        fclose(f);
    }
    return rv;
}

uasn1_item_t *uasn1_bn_to_asn1(BIGNUM *bn)
{
    int l,b;
    uasn1_item_t *integer;
    b = BN_num_bits(bn);
    l = ((b == 0)? 0 : (( b / 8 ) + 1));
    if((integer = uasn1_item_new(uasn1_integer_type))) {
        integer->value.string.flags = 0;
        integer->value.string.size = l + 4;
        integer->value.string.string = (unsigned char *)
            malloc((l + 4) * sizeof(unsigned char));
        if(integer->value.string.string == NULL) {
            free(integer);
            integer = NULL;
        } else {
            integer->value.string.size = BN_bn2bin(bn, integer->value.string.string);
            integer->value.string.flags = bn->neg;
        }
    }
    return integer;
}

#endif
