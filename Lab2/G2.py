def initialize_s_box(key):
    s_box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s_box[i] + key[i % len(key)]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    return s_box

def rc4(key, ciphertext):
    s_box = initialize_s_box(key)
    i = 0
    j = 0
    plaintext = bytearray()

    for byte in ciphertext:
        i = (i + 1) % 256
        j = (j + s_box[i]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
        key_byte = s_box[(s_box[i] + s_box[j]) % 256]
        plaintext.append(byte ^ key_byte)

    return bytes(plaintext)

def main():
    password = "napier"
    key = [ord(char) for char in password]  # Convert the password to a list of ASCII values
    ciphertext_hex = "8d1cc8bdf6da"
    ciphertext = bytes.fromhex(ciphertext_hex)

    decrypted_bytes = rc4(key, ciphertext)
    print("Decrypted Bytes:", decrypted_bytes.hex())

if __name__ == "__main__":
    main()