# use -hex for hexadecimal encoding; 32 bytes x 2 = 256 bits
# default is binary is you don't specify hexadecimal with -hex flag
# no limitation to length of random string
# is there really not? what about overflow?
openssl rand -base64 32

# For practical purposes 32 is more than enough
# As far as I can tell the upper limit for openssl number of bytes is 99999999999999999
https://stackoverflow.com/questions/3638622/do-ruby-objects-have-a-size-limit
# If you enter openssl rand -base64 999999999999999999 it fails with
usage: rand [-base64 | -hex] [-out file] num

echo "Hello world\!" > hello.txt

openssl dgst -sha256 hello.txt
openssl dgst -sha256 hello.txt > shasum

sha256sum -c shasum

# now edit hello.txt and add another !

sha256sum -c shasum

# File encryption using passwords

# encrypt the file wiuthout cachine the password locally
# if you don't use no-symkey-cache it will cache your password on your computer
# input is the file you pass in - hello.txt
# it will ask for the passphrase
# $ gpg --no-symkey-cache --cipher-algo AES256 -c hello.txt

# what it will do is create a file with a .gpg extension
# you can look at the content of that file with cat.txt
# this is a binary file - cat hello.txt.gpg | base64
# the output string is an encryption of hello world

# Use the same password to decrypt
gpg 
# encrypt the file without caching the password locally
$ gpg --no-symkey-cache --cipher-algo AES256 -c hello.txt
# Use the same password to decrypt
$ gpg -o output.txt -d hello.txt.gpg
# Check the encrypted text in base64
cat hello.txt.gpg | base64

# using rbnaacl
do SHA - quick hashing

message - 

in irb
or 
rbnacl is a ruby binding for libsodium

Such a bad science joke . Sodium/NaCl

# is incredibly slow on local devices - some things for AES - just edge case scenarios - 

# rbnacl is faster - this is a better place to start for Crypto in Ruby
# than OpenSSl
# with OpenSSL you tned to make lot of mistakes
require 'rbnacl'
require 'base64'
message='Hello World!'
RbNaCl::Hash.sha256(message)
RbNaCl::Hash.sha256(message).unpack('H*')
https://github.com/RubyCrypto/rbnacl

# Same-key encryption
# Generate a random symmetric key
key = RbNaCl::Random.random_bytes(RbNaCl::SecretBox.key_bytes)

# Create an encryption/decryption box from the key
# from key you create a box

box = RbNaCl::SimpleBox.from_secret_key(key)
# Encrypt the message
ciphertext = box.encrypt(message)
# Decrypt the ciphertext
box.decrypt(ciphertext)

# Alice generates a random private key
alice_private_key = RbNaCl::PrivateKey.generate()
# Alice derives the public key
alice_public_key = alice_private_key.public_key()
# Alice shares the public key with the world
alice_public_key_base64 = Base64.urlsafe_encode64(alice_public_key.to_bytes)

get his public key and your _ key and using those create a box
bob_public_key_base64
alice_box = RbNaCl::SimpleBox.from_keypair(
    Base64.urlsafe_decode64(bob_public_key_base64),
    alice_private_key)

message = 'what do computers have for lunch?.... fission chips'

# encrypt the message

ciphertext = alice_box.encrypt(message)

ciphertext_base64 = Base64.urlsafe_encode64(ciphertext)

alice_public_key
Base64.urlsafe_encode64(alice_public_key.to_bytes)

alice_public_key_base64 = "your public key"
ciphertext_base64 = "message you sent me"

first create a decryption box
bob_box = RbN

alice_public_key_base64 = "_your public key_"
ciphertext_base64 = "_message you sent me_"
# first create a decryption box
bob_box = RbNaCl::SimpleBox.from_keypair(
        Base64.urlsafe_decode64(alice_public_key_base64), 
        bob_private_key)
bob_box.decrypt(Base64.urlsafe_decode64(ciphertext_base64))

# we never share private keys with eachother, we only have public keys with eachother

# Signing - next thing you can do is signing
# you first create a signing key which is a private key
you need to keys - x key to sign, and private key to verify
you call sign which is a signature

then you send the message, your signature and your verify (public) key
anyone who knows these can authenticate that a document or message comes from somebody with the private key


# message authentication code - equivalent of signing
you use the same key to sign, and verify.

if you use messsage authenitcation code you're effectively signing 
message authentication a bit like hashing - lets you be sure the message of the file you're reading is one from you


tun.loakthar:spiral_calendar_pad:  12:35
# Create a random private key
key = RbNaCl::Random.random_bytes(RbNaCl::SecretBox.key_bytes)
# Create authentication object
authentication = = RbNaCl::HMAC::SHA256.new(key)
# Compute authenticator
authenticator = authentication.update(message)
# Verify
authentication.verify_message(authenticator, message)

general notes
good real world example i've seen is journalists on twitter providing a key for securely contacting them https://jacob.hoffman-andrews.com/README/the-safe-way-to-put-a-pgp-key-in-your-twitter-bio/
