PROGS=obtest-gcm

CC=clang
CFLAGS=-c -g \
  -D MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS \
  -I ../../src-crypto/include -I ../../opt/openbadger/include -I/usr/include/PCSC -Wall -Werror
LINK=clang
LDFLAGS=-g -L ../../opt/openbadger/lib -lopenbadger-crypto-lite -lmbedcrypto

all:	${PROGS}

clean:
	rm -f ${PROGS} *.o core 

obtest-gcm:	obtest-gcm.o Makefile
	${LINK} -o obtest-gcm obtest-gcm.o ${LDFLAGS}

obtest-gcm.o:	obtest-gcm.c
	${CC} ${CFLAGS} obtest-gcm.c

