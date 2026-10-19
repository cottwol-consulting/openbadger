CC=clang
CFLAGS=-c -g -I../include -I../opt/openbadger/include -I/opt/crypto/include -I/usr/include/PCSC -Wall -Werror

all:	ob-dualkey.o
	ar r libopenbadger-crypto-lite.a ob-dualkey.o
	(cd src-ec; make library)
	(cd src-rsa; make library)
	(cd src-mbedtls; make library)
	mkdir -p ../opt/openbadger/lib
	cp libopenbadger-crypto-lite.a ../opt/openbadger/lib
	mkdir -p ../opt/openbadger/include
	cp include/*h ../opt/openbadger/include

clean:
	rm -f core *.a *.o
	(cd src-ec; make clean)
	echo not src-rsa?
	(cd src-rsa; make clean)
	(cd src-mbedtls; make clean)

ob-dualkey.o:	ob-dualkey.c
	${CC} ${CFLAGS} ob-dualkey.c

