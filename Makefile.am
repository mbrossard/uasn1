ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = ${my_CFLAGS} \
	-I$(srcdir)/src

noinst_LIBRARIES = libuasn1.a

libuasn1_a_SOURCES = src/uasn1.c \
	src/base64.c \
	src/crl.c \
	src/cryptoki.c \
	src/decode.c \
	src/encode.c \
	src/key.c \
	src/ocsp.c \
	src/oids.c \
	src/oidsdb.c \
	src/pkix.c \
	src/request.c \
	src/tsa.c \
	src/utils.c \
	src/x509.c

noinst_PROGRAMS = tests/test_asn1 \
	tests/test_base64 \
	tests/test_cryptoki

tests_test_asn1_SOURCES = tests/test_asn1.c
tests_test_asn1_LDADD = libuasn1.a

tests_test_base64_SOURCES = src/base64.c
tests_test_base64_CFLAGS = -DBASE64_TEST

tests_test_cryptoki_SOURCES = tests/test_cryptoki.c \
	tests/ocsp_test.c \
	tests/tsa_test.c \
	tests/x509_test.c

tests_test_cryptoki_LDADD = libuasn1.a

test: $(noinst_PROGRAMS)
	./tests/test_asn1
	./tests/test_base64
	./tests/test_cryptoki
