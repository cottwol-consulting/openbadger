#!/bin/bash
set -x

# this extracts the public key from the certifiate
# used in cases where the certificate will not parse (I'm looking at you, WolfSSL)

openssl x509 -inform DER -in cert.der -pubkey -noout -out public-key.pem
openssl ec -inform PEM -pubin -in public-key.pem -outform DER -out public-key.der
