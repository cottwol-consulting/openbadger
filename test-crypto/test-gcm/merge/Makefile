PROGS=obtest-gcm

CC=clang
CFLAGS=-c -g -I/opt/openbadger/include -I/usr/include/PCSC -Wall -Werror
LINK=clang
LDFLAGS=-g -lmbedcrypto

all:	${PROGS}

clean:
	rm -f ${PROGS} a.out *.o

obtest-gcm:	obtest-gcm.o Makefile
	${LINK} -o obtest-gcm obtest-gcm.o ${LDFLAGS}

obtest-gcm.o:	obtest-gcm.c
	${CC} ${CFLAGS} obtest-gcm.c

