# make file for rsa crypto testing

PROGS= \
  obtest-rsa

CC=clang
CFLAGS=-c -DWOLFSSL_USE_OPTIONS_H -g -I ../../opt/openbadger/include -I/opt/crypto/include -I/usr/include/PCSC -Wall -Werror
LINK=clang
LDFLAGS=-g -L ../../opt/openbadger/lib -lopenbadger -lopenbadger-crypto-lite -L /opt/crypto/lib -lwolfssl -ljansson
PACKAGE_ROOT=../../opt/openbadger

all:	${PROGS}
	mkdir -p ${PACKAGE_ROOT}/bin
	cp ${PROGS} ${PACKAGE_ROOT}/bin

clean:
	rm -f a.out *.o ${PROGS}

obtest-rsa:	obtest-rsa.o Makefile
	${LINK} -o obtest-rsa obtest-rsa.o ${LDFLAGS}

obtest-rsa.o:	obtest-rsa.c
	${CC} ${CFLAGS} obtest-rsa.c

