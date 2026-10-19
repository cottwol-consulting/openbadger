#!/bin/bash
set -x
ob-reader --help
ob-reader --verbosity=9
ob-reader --settings test-ob-reader.json
ob-reader --reader 1
ob-reader --format 128
ob-reader --osdp
ob-reader --mechanism pkoc
ob-reader --osdp=/opt/cabana17/PD-0B
ob-reader --signer thing2.der

