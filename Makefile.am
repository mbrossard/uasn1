AM_CFLAGS = ${my_CFLAGS} \
	-I$(srcdir)/src

noinst_LIBRARIES = libuasn1.a

libuasn1_a_SOURCES = src/uasn1.c \
	src/encode.c \
	src/decode.c

noinst_PROGRAMS = tests/test_asn1

tests_test_asn1_SOURCES = tests/test_asn1.c
tests_test_asn1_LDADD = libuasn1.a
