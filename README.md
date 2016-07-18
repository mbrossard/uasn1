# uasn1

uasn1 is a small BER/DER ASN.1 encoding/parsing library in C, with
mostly PKI applications in mind.

[![Build Status](https://travis-ci.org/mbrossard/uasn1.svg?branch=master)](https://travis-ci.org/mbrossard/uasn1)

Known limitations:

  * OIDs must have components small enough to fit in a unisgned int.
  * The only supported algorithms are SHA1 and RSA.
  * No string format validations are performed.
  * Only a very small subset is supported.
  * Leaks a lot of memory.
