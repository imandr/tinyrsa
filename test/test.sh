#!/bin/bash

echo
echo Generating key pair ...
tinyrsa generate -k keys
cat keys

echo
echo Extracting public key ...
tinyrsa public -k keys -o public
cat public

echo
echo Encryping story ...
tinyrsa encrypt -k public story encrypted
ls -l story encrypted

echo
echo Decrypting story ...
tinyrsa decrypt -k keys encrypted decrypted
ls -l story encrypted decrypted

echo
echo Comparing ...
diff story decrypted

echo
echo Signing story ...
tinyrsa sign -k keys story signature
cat signature

echo
echo Verifying signarute
tinyrsa verify -k public story signature