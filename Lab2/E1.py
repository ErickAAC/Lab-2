from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

import hashlib
import binascii

val= input("enter cipher text:  ")
password=input("enter the encryption key:  ")

plaintext=val


def decrypt(ciphertext,key, mode):
    method=algorithms.TripleDES(key)
    cipher = Cipher(method, mode, default_backend())
    decryptor = cipher.decryptor()
    pl = decryptor.update(ciphertext) + decryptor.finalize()
    return(pl)

def unpad(data,size=64):
    padder = padding.PKCS7(size).unpadder()
    unpadded_data = padder.update(data)
    unpadded_data += padder.finalize()
    return(unpadded_data)

key = hashlib.sha256(password.encode()).digest()[:16]

ciphertext1 = binascii.unhexlify("0b8bd1e345e7bbf0")
plaintext = decrypt(ciphertext1,key,modes.ECB())

plaintext = unpad(plaintext)
print("  decrypt: ",plaintext.decode())