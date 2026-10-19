all:
	echo Build cryptograpy tests
	(cd test-gcm; make)
	(cd test-ec; make)
	(cd test-rsa; make)
	(cd test-key-exchange; make);

clean:
	(cd test-gcm; make clean)
	(cd test-ec; make clean)
	(cd test-rsa; make clean)
	(cd test-key-exchange; make clean);

