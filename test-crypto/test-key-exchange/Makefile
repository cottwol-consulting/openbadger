# make file for key exchange testing

PROGS= \
  obkex-initiator obkex-responder

CC=clang
CFLAGS=-c -DWOLFSSL_USE_OPTIONS_H -g -I../include -I ../../opt/openbadger/include -I/opt/crypto/include -I/usr/include/PCSC -Wall -Werror
LINK=clang
LDFLAGS=-g -L ../../opt/openbadger/lib -lopenbadger-crypto-lite -lopenbadger -L /opt/crypto/lib -lwolfssl -ljansson
PACKAGE_ROOT=../../opt/openbadger

all:	${PROGS}
	mkdir -p ${PACKAGE_ROOT}/bin
	cp ${PROGS} ${PACKAGE_ROOT}/bin

clean:
	rm -f a.out *.o ${PROGS}

obkex-initiator:	obkex-initiator.o Makefile openbadger-key-exchange-utils.o
	${LINK} -o obkex-initiator obkex-initiator.o openbadger-key-exchange-utils.o ${LDFLAGS}

obkex-initiator.o:	obkex-initiator.c
	${CC} ${CFLAGS} obkex-initiator.c

obkex-responder:	obkex-responder.o Makefile openbadger-key-exchange-utils.o
	${LINK} -o obkex-responder obkex-responder.o openbadger-key-exchange-utils.o  ${LDFLAGS}

obkex-responder.o:	obkex-responder.c
	${CC} ${CFLAGS} obkex-responder.c

openbadger-key-exchange-utils.o:	openbadger-key-exchange-utils.c
	${CC} ${CFLAGS} openbadger-key-exchange-utils.c

