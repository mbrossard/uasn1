define([UASN1_VERSION_MAJOR], [0])
define([UASN1_VERSION_MINOR], [1])
define([UASN1_VERSION_PATCH], [0])
define([VERSION_SUFFIX], [])

define([LIB_VERSION_CURRENT], [1])
define([LIB_VERSION_AGE], [1])
define([LIB_VERSION_REVISION], [0])

AC_PREREQ(2.64)
AC_INIT([uasn1],[UASN1_VERSION_MAJOR.UASN1_VERSION_MINOR.UASN1_VERSION_PATCH[]VERSION_SUFFIX])
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign 1.11 -Wall -Wno-portability silent-rules tar-pax no-dist-gzip dist-xz subdir-objects)
AC_USE_SYSTEM_EXTENSIONS

VERSION_INFO="LIB_VERSION_CURRENT:LIB_VERSION_REVISION:LIB_VERSION_AGE"
AC_SUBST([VERSION_INFO])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_RANLIB
if test x"$pkcs11_module" == x""; then
   AC_PATH_PROG([PKG_CONFIG], [pkg-config])
   if test x"$PKG_CONFIG" != x""; then
       NSS_LIBDIR=`$PKG_CONFIG nss --variable=libdir 2>/dev/null`
       if test x"NSS_LIBDIR" != x""; then
           if test `uname` == "Darwin" ; then
              NSS_LIBNAME="libsoftokn3.dylib" ;
           else
              NSS_LIBNAME="libsoftokn3.so" ;
              if test ! -f "$NSS_LIBDIR/$NSS_LIBNAME" -a -f "$NSS_LIBDIR/nss/$NSS_LIBNAME" ; then
                  NSS_LIBNAME="nss/$NSS_LIBNAME" ;
              fi
           fi
           pkcs11_module="$NSS_LIBDIR/$NSS_LIBNAME"
       fi
       if test ! -f "$pkcs11_module" ; then
           if test `uname` == "Darwin" ; then
              pkcs11_module=`ls -1 /usr/local/Cellar/nss/*/lib/libsoftokn3.dylib | sort | tail -1` ;
           else
              pkcs11_module=`ls -1 /usr/lib*/*/nss/libsoftokn3.so | sort | tail -1` ;
           fi
       fi
   fi
fi

if test x"$pkcs11_module" != x"" -a -f "$pkcs11_module"; then
   pkcs11_path=`echo $pkcs11_module | sed 's|\\\\|\\\\\\\\|g'`
   AC_DEFINE_UNQUOTED([DEFAULT_PKCS11_MODULE], "${pkcs11_path}", [Default PKCS#11 module])
   DEFAULT_PKCS11_MODULE="${pkcs11_module}"
fi
AC_SUBST([DEFAULT_PKCS11_MODULE])

AX_CHECK_OPENSSL
CFLAGS="${CFLAGS} ${OPENSSL_INCLUDES}"
LDFLAGS="${LDFLAGS} ${OPENSSL_LDFLAGS}"
LIBS="${LIBS} ${OPENSSL_LIBS}"
if test x"$OPENSSL_LIBS" != x""; then
   AC_DEFINE_UNQUOTED([HAVE_OPENSSL], [1], [Compiled with OpenSSL])
fi

AC_CONFIG_FILES([Makefile])
AC_CACHE_SAVE
AC_OUTPUT

AC_MSG_RESULT([
        $PACKAGE $VERSION
        =====

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}
        libs:                   ${LIBS}

        openssl binary:         ${OPENSSL_BIN}
])
