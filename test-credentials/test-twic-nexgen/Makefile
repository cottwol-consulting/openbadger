# obtest-twic -TWIC NEXGEN Card Exerciser

# (C)2026 Cottwol Consulting

PROGS=obtest-twic 

COMMON_INCLUDE=../../include
OB_INCLUDES=\
  ${COMMON_INCLUDE}/ob-73-4.h ${COMMON_INCLUDE}/ob-7816.h ${COMMON_INCLUDE}/ob-pcsc.h \
  ${COMMON_INCLUDE}/openbadger-common.h 
CC=clang
CFLAGS=-DUSE_WOLFSSL -DWOLFSSL_ASN_TEMPLATE -DWOLFSSL_CUSTOM_OID -DWOLFSSL_PUBLIC_ASN -DWC_ASN_UNKNOWN_EXT_CB \
  -c -g -I${COMMON_INCLUDE} -I/opt/crypto/include -I/usr/include/PCSC -Wall -Werror
LINK=clang
LINK_WITH_MBEDTLS= -lmbedtls -lmbedx509 -lmbedcrypto 
LINK_WITH_WOLFSSL=-L/opt/crypto/lib -lwolfssl
LDFLAGS=-g -L ../../opt/openbadger/lib -lopenbadger \
  ${LINK_WITH_WOLFSSL} \
  -ljansson -lpcsclite -lz
PACKAGE_ROOT=../../opt/openbadger

all:	${PROGS}
	mkdir -p ${PACKAGE_ROOT}/bin
	cp ${PROGS} ${PACKAGE_ROOT}/bin

clean:
	rm -f core *.o ${PROGS}

package:
	mkdir -p ../opt/tester/bin
	cp ${PROGS} ../opt/tester/bin

obtest-twic:	Makefile obtest-twic.o ob-twic-support.o
	${LINK} -o obtest-twic obtest-twic.o ob-twic-support.o ${LDFLAGS}

obtest-twic.o:	obtest-twic.c ${OB_INCLUDES} \
	  ${COMMON_INCLUDE}/openbadger-version.h
	${CC} ${CFLAGS} obtest-twic.c

ob-twic-support.o:	ob-twic-support.c ${OB_INCLUDES}
	${CC} ${CFLAGS} ob-twic-support.c

