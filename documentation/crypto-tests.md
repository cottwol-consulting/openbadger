#!/bin/bash
set -x

echo generate P256R1 key pair
openssl ecparam -name prime256v1 -genkey -noout -out ec_private_secp256r1.pem
openssl ec -in ec_private_secp256r1.pem -pubout -out ec_public_secp256r1.pem
openssl ec -pubin -in ec_public_secp256r1.pem -outform DER -out ec_pubkey.der
openssl ec -in ec_private_secp256r1.pem -outform DER -out ec_private_secp256r1.der

echo generate brainpool-P256r1 key pair
openssl ecparam -name brainpoolP256r1 -genkey -noout -out brainpool_private.pem
openssl ec -in brainpool_private.pem -pubout -out brainpool_public.pem
openssl ec -pubin -in brainpool_public.pem -outform DER -out brainpool_public.der
openssl ec -in brainpool_private.pem -outform DER -out brainpool_private.der

echo sign a test message
echo 123 >message.bin
openssl dgst -sha256 -sign ec_private_secp256r1.pem -out signature.bin message.bin
openssl dgst -sha256 -sign brainpool_private.pem -out brainpool_sig.bin message.bin

ls -l ec*pem ec*der *.bin


