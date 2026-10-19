PROGS=ob-reader
PACKAGE_ROOT=../opt/openbadger

CC=clang
CFLAGS=-c -g -Wall -Werror
LINK=clang
LDFLAGS=-g

all:	${PROGS}
	mkdir -p ${PACKAGE_ROOT}/bin
	cp ${PROGS} ${PACKAGE_ROOT}/bin

clean:
	rm -f a.out core *.o ${PROGS}

test:	all
	PATH=.:$PATH ./test.sh 

ob-reader:	ob-reader.o Makefile
	${LINK} -o ob-reader ob-reader.o ${LDFLAGS}

ob-reader.o:	ob-reader.c
	${CC} ${CFLAGS} ob-reader.c

