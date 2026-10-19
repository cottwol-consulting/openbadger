PROGS=test-ec test-ec-jwk

CC=clang
CFLAGS=-c -DWOLFSSL_USE_OPTIONS_H -g -I ../../opt/openbadger/include  -I/opt/crypto/include -I/usr/include/PCSC -Wall -Werror
LINK=clang
LDFLAGS=-g -L ../../opt/openbadger/lib -lopenbadger-crypto-lite -lopenbadger -L /opt/crypto/lib -lwolfssl -ljansson

all:	${PROGS}

clean:
	rm -f ${PROGS} *.o core 

test-ec:	test-ec.o Makefile
	${LINK} -o test-ec test-ec.o ${LDFLAGS}

test-ec-jwk:	test-ec-jwk.o Makefile
	${LINK} -o test-ec-jwk test-ec-jwk.o ${LDFLAGS}

test-ec.o:	test-ec.c ../../opt/openbadger/include/ob-crypto-ec.h
	${CC} ${CFLAGS} test-ec.c

test-ec-jwk.o:	test-ec-jwk.c ../../opt/openbadger/include/ob-crypto-ec.h
	${CC} ${CFLAGS} test-ec-jwk.c

