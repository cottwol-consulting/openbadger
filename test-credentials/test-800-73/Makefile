# test-800-73 - testing of "PIV" cards

# (C)2023-2026 Smithee Solutions LLC

PROGS=obtest-challenge obtest-getcert obtest-pk-pacs

COMMON_INCLUDE=../../include
CC=clang
# PCSC is included because their own includes get it wrong
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

obtest-challenge:	Makefile obtest-challenge.o ob-genauth.o
	${LINK} -o obtest-challenge obtest-challenge.o ob-genauth.o ${LDFLAGS}

obtest-pk-pacs:	Makefile obtest-pk-pacs.o ob-piv-utils.o
	${LINK} -o obtest-pk-pacs obtest-pk-pacs.o ob-piv-utils.o ${LDFLAGS}

obtest-getcert:	Makefile obtest-getcert.o ob-genauth.o ob-piv-utils.o
	${LINK} -o obtest-getcert obtest-getcert.o ob-genauth.o ob-piv-utils.o ${LDFLAGS}

ob-genauth.o:	ob-genauth.c \
	${COMMON_INCLUDE}/ob-73-4.h ${COMMON_INCLUDE}/ob-7816.h ${COMMON_INCLUDE}/ob-pcsc.h ${COMMON_INCLUDE}/openbadger-common.h
	${CC} ${CFLAGS} ob-genauth.c

obtest-challenge.o:	obtest-challenge.c \
	${COMMON_INCLUDE}/ob-73-4.h ${COMMON_INCLUDE}/ob-7816.h ${COMMON_INCLUDE}/ob-pcsc.h \
	  ${COMMON_INCLUDE}/openbadger-common.h ${COMMON_INCLUDE}/openbadger-version.h
	${CC} ${CFLAGS} obtest-challenge.c

obtest-pk-pacs.o:	obtest-pk-pacs.c \
	${COMMON_INCLUDE}/ob-73-4.h ${COMMON_INCLUDE}/ob-7816.h ${COMMON_INCLUDE}/ob-pcsc.h \
	  ${COMMON_INCLUDE}/openbadger-common.h ${COMMON_INCLUDE}/openbadger-version.h
	${CC} ${CFLAGS} obtest-pk-pacs.c

obtest-getcert.o:	obtest-getcert.c \
	${COMMON_INCLUDE}/ob-73-4.h ${COMMON_INCLUDE}/ob-7816.h ${COMMON_INCLUDE}/ob-pcsc.h \
	  ${COMMON_INCLUDE}/openbadger-common.h ${COMMON_INCLUDE}/openbadger-version.h
	${CC} ${CFLAGS} obtest-getcert.c

ob-piv-utils.o:	ob-piv-utils.c
	${CC} ${CFLAGS} ob-piv-utils.c

