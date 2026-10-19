integrated for EC operations, certificate parsing.
cannot handle LEAF subjectName (reported.)

build wolfssl like this:

EXTRA_CFLAGS=-DWC_ASN_UNKNOWN_EXT_CB ./configure --prefix=/opt/crypto --enable-ecccustcurves --enable-debug --enable-certgen 

