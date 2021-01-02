#!/bin/bash

echo
echo Generating key pair for Alice ...
tinyrsa generate -k alice
cat alice

echo
echo Generating key pair for Bob ...
tinyrsa generate -k bob
cat bob

echo
echo Private keys are kept secret
ls -l alice bob

echo
echo Extracting public keys for Alice and Bob ...
tinyrsa public -k alice -o alice.public
tinyrsa public -k bob -o bob.public
cat alice.public
cat bob.public

echo
echo Alice and Bob publish their public keys on the Internet ...
ls -l alice.public bob.public

echo
echo Alice encrypts story for Bob ...
tinyrsa encrypt -k bob.public story encrypted
ls -l story encrypted

echo
echo Alice signs story ...
tinyrsa sign -k alice story signature
cat signature

echo
echo Alice sends the encrypted story and the signature to Bob somehow ...

echo
echo Bob decrypts the story ...
tinyrsa decrypt -k bob encrypted decrypted
ls -l encrypted decrypted

echo
echo "Bob verifies Alice's signarute ..."
tinyrsa verify -k alice.public decrypted signature

echo
echo "Bob reads the story ..."

cat story




