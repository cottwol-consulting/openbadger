PROGS=ob-bin2include ob-cert-dump ob-hex2bin ob-ec-raw2der

CC=clang
CFLAGS=-c -g -I../opt/openbadger/include -I/usr/include/PCSC -Wall -Werror
LINK=clang
LDFLAGS=-g ../opt/openbadger/lib/base64.o \
  -L../opt/openbadger/lib -lopenbadger -lopenbadger-crypto-lite  -lmbedx509 -lmbedcrypto
PACKAGE_ROOT=../opt/openbadger

all:	${PROGS}
	mkdir -p ${PACKAGE_ROOT}/bin
	cp ${PROGS} ${PACKAGE_ROOT}/bin

clean:
	rm -f core *.o a.out ${PROGS}

ob-bin2include:	ob-bin2include.o Makefile
	${LINK} -o ob-bin2include ob-bin2include.o ${LDFLAGS}

ob-cert-dump:	ob-cert-dump.o Makefile
	${LINK} -o ob-cert-dump ob-cert-dump.o ${LDFLAGS}

ob-cert-dump.o:	ob-cert-dump.c
	${CC} ${CFLAGS} ob-cert-dump.c

ob-ec-raw2der:	ob-ec-raw2der.o Makefile
	${LINK} -o ob-ec-raw2der ob-ec-raw2der.o ${LDFLAGS}

ob-hex2bin:	ob-hex2bin.o Makefile
	${LINK} -o ob-hex2bin ob-hex2bin.o ${LDFLAGS}

ob-bin2include.o:	ob-bin2include.c
	${CC} ${CFLAGS} ob-bin2include.c

ob-ec-raw2der.o:	ob-ec-raw2der.c
	${CC} ${CFLAGS} ob-ec-raw2der.c

ob-hex2bin.o:	ob-hex2bin.c
	${CC} ${CFLAGS} ob-hex2bin.c

