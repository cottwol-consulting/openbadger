#!/bin/bash
set -x
openssl genrsa -out sample_keypair.pem 2048
openssl rsa -in sample_keypair.pem -inform PEM -pubout -outform DER -out sample_pubkey.der
openssl rsa -in sample_keypair.pem -inform PEM -outform DER -out sample_privkey.der

