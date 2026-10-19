# common routines for openbadger

# (c)2026 Cottwol Consulting

CC=clang
# PCSC is included because their own includes get it wrong
CFLAGS= \
  -c -g -I../include -I /opt/openbadger/include -I/usr/include/PCSC -Wall -Werror

all:	libopenbadger.a
	(cd Base64; make)

clean:
	rm -f core *.o *.a
	(cd Base64; make clean)

libopenbadger.a:	ob-encode-prims.o ob-key-utils.o ob-osdp.o ob-settings.o ob-smartcard-utils.o ob-utils.o \
	  Base64/base64.o
	ar r libopenbadger.a \
	  ob-encode-prims.o ob-osdp.o ob-settings.o ob-key-utils.o ob-smartcard-utils.o ob-utils.o \
	  Base64/base64.o
	mkdir -p ../opt/openbadger/lib
	cp libopenbadger.a ../opt/openbadger/lib

ob-encode-prims.o:	ob-encode-prims.c \
	../include/ob-73-4.h ../include/ob-7816.h ../include/ob-pcsc.h ../include/openbadger-common.h
	${CC} ${CFLAGS} ob-encode-prims.c

ob-key-utils.o:	ob-key-utils.c \
	../include/ob-73-4.h ../include/ob-7816.h ../include/ob-pcsc.h ../include/openbadger-common.h
	${CC} ${CFLAGS} ob-key-utils.c

ob-osdp.o:	ob-osdp.c \
	../include/ob-73-4.h ../include/ob-7816.h ../include/ob-pcsc.h ../include/openbadger-common.h
	${CC} ${CFLAGS} ob-osdp.c

ob-settings.o:	ob-settings.c \
	../include/ob-73-4.h ../include/ob-7816.h ../include/ob-pcsc.h ../include/openbadger-common.h
	${CC} ${CFLAGS} ob-settings.c

ob-smartcard-utils.o:	ob-smartcard-utils.c \
	../include/ob-73-4.h ../include/ob-7816.h ../include/ob-pcsc.h ../include/openbadger-common.h
	${CC} ${CFLAGS} ob-smartcard-utils.c

ob-utils.o:	ob-utils.c \
	../include/ob-73-4.h ../include/ob-7816.h ../include/ob-pcsc.h ../include/openbadger-common.h
	${CC} ${CFLAGS} ob-utils.c

