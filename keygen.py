# генератор ключей

from Crypto.PublicKey import RSA

key = RSA.generate(1024)
with open('mykey.pem','wb') as f:
    f.write(key.exportKey('PEM'))
with open('pubkey.pem','wb') as f:
    f.write(key.publickey().exportKey('PEM'))
