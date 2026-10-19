# make file for mbedtls

OBJECTS=ob-cert-read.o
OB_INCLUDE_DIR=../../opt/openbadger/include

CC=clang
CFLAGS=-c -g -I../../opt/openbadger/include -I/usr/include/PCSC -Wall -Werror

all:	${OBJECTS}

library:	all
	ar r ../libopenbadger-crypto-lite.a ${OBJECTS}
	mkdir -p ${OB_INCLUDE_DIR}

clean:
	rm -f core ${OBJECTS}

ob-cert-read.o:	ob-cert-read.c
	${CC} ${CFLAGS} ob-cert-read.c

