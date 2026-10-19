# make file for EC crypto
# Uses wolfssl
# see provenance.md for crypto code sources

OBJECTS=ob-dualkey-ec.o ob-ec-utils.o
OB_INCLUDE_DIR=../../opt/openbadger/include

CC=clang
CFLAGS=-c -g \
  -I../include -I../../include -I../../opt/openbadger/include \
  -I/opt/crypto/include -I/usr/include/PCSC -Wall -Werror

all:	${OBJECTS}

library:	all
	ar r ../libopenbadger-crypto-lite.a ${OBJECTS}
	mkdir -p ${OB_INCLUDE_DIR}

clean:
	rm -f core ${OBJECTS}

ob-dualkey-ec.o:	ob-dualkey-ec.c
	${CC} ${CFLAGS} ob-dualkey-ec.c

ob-ec-utils.o:	ob-ec-utils.c
	${CC} ${CFLAGS} ob-ec-utils.c

