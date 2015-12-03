AM_CFLAGS = ${my_CFLAGS} \
	-I$(srcdir)/src

noinst_LIBRARIES = libuasn1.a

libuasn1_a_SOURCES = src/uasn1.c \
	src/base64.c \
	src/encode.c \
	src/decode.c

noinst_PROGRAMS = tests/test_asn1 \
	tests/test_base64

tests_test_asn1_SOURCES = tests/test_asn1.c
tests_test_asn1_LDADD = libuasn1.a

tests_test_base64_SOURCES = src/base64.c
tests_test_base64_CFLAGS = -DBASE64_TEST

test: $(noinst_PROGRAMS)
	(cd tests ; ./test_asn1)
	(cd tests ; ./test_base64)
