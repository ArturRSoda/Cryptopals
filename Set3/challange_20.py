from utils import attack_single_byte_key_xor, encrypt_AES_CTR
from base64 import b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = AES.block_size

def get_cipher_and_plain_texts() -> list[bytes]:
    f = open("20.txt", "r")
    plainText = [b64decode(line) for line in f.read().split('\n')]
    f.close()

    key = get_random_bytes(BLOCK_SIZE)
    nonce = bytes(BLOCK_SIZE//2)
    cipher = [encrypt_AES_CTR(pt, key, nonce) for pt in plainText]

    return cipher

def main() -> None:
    cipherTexts = get_cipher_and_plain_texts()[:-1]
    transposedCipherTexts = list(zip(*cipherTexts))

    transposedPlainTexts = [attack_single_byte_key_xor(cipher)[0] for cipher in transposedCipherTexts]
    plainText = list(zip(*transposedPlainTexts))
    for msg in plainText:
        print(bytes(msg).decode())


main()
