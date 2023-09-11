# https://asecuritysite.com/encryption/salsa20
import binascii

from Crypto.Cipher import Salsa20
import hashlib
from base64 import b64encode
from Crypto.Cipher import ChaCha20

plaintext = b'apple'
key= b'qwerty'

print("Plain key:\t",plaintext)
print("Secret key:\t",key)

secret = hashlib.sha256()

secret.update(key)

print("Key used:\t",b64encode(secret.digest()))

cipher = Salsa20.new(key=secret.digest())
enc=cipher.encrypt(plaintext)


ct = b64encode(enc).decode('utf-8')
nonce = b64encode(cipher.nonce).decode('utf-8')
print("\n---Salsa20 Encrypt")
print(" Nonce:",nonce)
print(" Cipher:",ct)


print("\n---Salsa20 Decrypt")
cipher = Salsa20.new(key=secret.digest(), nonce=cipher.nonce)
plaintext = cipher.decrypt(enc)
print(" Decrypted:\t",plaintext)



cipher = ChaCha20.new(key=secret.digest())
ciphertext = cipher.encrypt(plaintext)
print(ciphertext)
nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ciphertext).decode('utf-8')
print("\n---ChaCha20 Encrypt")
print(" Nonce:",nonce)
print(" Cipher:",ct)
cg= binascii.unhexlify('e47a2bfe646a')
print(cg)
print("\n---ChaCha20 Decrypt")
cipher = ChaCha20.new(key=secret.digest(), nonce=cipher.nonce)
plaintext = cipher.decrypt(cg)
ct2 = b64encode(plaintext).decode('utf-8')
print(" Decrypted:\t",ct2)