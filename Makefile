# makefile - make openbadger

# (C)Copyright 2026 Cottwol Consulting

PACKAGE_ROOT=opt/openbadger
INCLUDE_FILES= \
	include/openbadger-common.h include/openbadger-version.h \
	include/ob-crypto.h include/ob-encode.h include/ob-pcsc.h include/ob-7816.h \
	common/Base64/base64.h

all:
	mkdir -p ${PACKAGE_ROOT}/include
	cp ${INCLUDE_FILES} ${PACKAGE_ROOT}/include
	(cd common; make)
	(cd src-crypto; make)
	(cd src-tools; make);
	(cd test-crypto; make)
	(cd test-formats; make)
	(cd test-credentials; make)
	(cd src-reader; make)
	(cd documentation; make);

clean:
	(cd common; make clean);
	(cd src-crypto; make clean)
	(cd src-tools; make clean)
	(cd test-crypto; make clean)
	(cd test-formats; make clean)
	(cd test-credentials; make clean)
	(cd src-reader; make clean)
	(cd documentation; make clean);
	(cd package; make clean)
	rm -rf opt *deb

package:	all
	(cd documentation; make package)
	(cd package; make package)

