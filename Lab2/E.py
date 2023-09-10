from Crypto.Cipher import AES
import binascii
import hashlib
import sys
import Padding

def decrypt_aes_ecb(ciphertext, key):
    try:
        # Ensure the key length is 32 bytes (256 bits)
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits) long")

        # Convert the ciphertext from hex to bytes
        ciphertext_bytes = binascii.unhexlify(ciphertext)

        # Initialize the AES cipher in ECB mode with the provided key
        cipher = AES.new(key, AES.MODE_ECB)

        # Decrypt the ciphertext
        decrypted_data = cipher.decrypt(ciphertext_bytes)

        return decrypted_data
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    ciphertext = input("enter cipher text:  ")
    password = input("enter the encryption key:  ")

    # Derive the 256-bit AES key from the password using PBKDF2
    salt = b'SomeSaltHere'  # You can change the salt value
    key = key = hashlib.sha256(password.encode()).digest()

    decrypted_data = decrypt_aes_ecb(ciphertext, key)
    plaintext = Padding.removePadding(decrypted_data.decode(), mode='CMS')
    print("  decrypt: ", plaintext)
