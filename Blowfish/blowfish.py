#!/usr/bin/env python

from Crypto.Cipher import Blowfish
import base64

def pkcs5pad(s):
    return s + (8 - len(s) % 8) * chr(8 - len(s) % 8)

def pkcs5unpad(s):
    return s[0:-ord(s[-1])]

def encrypt(plaintext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    ciphertext = cipher.encrypt(pkcs5pad(plaintext))
    return (base64.b64encode(ciphertext)).decode("utf-8")

def decrypt(ciphertext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    paddedstring = cipher.decrypt(base64.b64decode(ciphertext))
    return pkcs5unpad(paddedstring).decode("utf-8")

def main():
    pt = 'nilesh'
    print(encrypt(pt, 'mykey123'))

if __name__ == '__main__':
    main()