# make file for RSA crypto
# Uses wolfssl
# see ../src-ec/provenance.md for crypto code sources

OBJECTS=ob-dualkey-rsa.o

CC=clang
CFLAGS=-c -g -I../include -I../../include -I../../opt/openbadger/include -I/opt/crypto/include -I/usr/include/PCSC -Wall -Werror

all:	${OBJECTS}

library:	all
	ar r ../libopenbadger-crypto-lite.a ${OBJECTS}

clean:
	rm -f core ${OBJECTS}

ob-dualkey-rsa.o:	ob-dualkey-rsa.c
	${CC} ${CFLAGS} ob-dualkey-rsa.c

