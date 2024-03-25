from utils import encrypt_AES_CTR, attack_single_byte_key_xor
from base64 import b64decode

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

BLOCK_SIZE = AES.block_size


def get_cipher_and_plain_textes() -> list[bytes]:
    f = open("19.txt", "r")
    plainText = [b64decode(line) for line in f.read().split('\n')]
    f.close()

    key = get_random_bytes(BLOCK_SIZE)
    nonce = get_random_bytes(BLOCK_SIZE//2)
    cipherText = [encrypt_AES_CTR(pt, key, nonce) for pt in plainText]

    return cipherText

def do_evil(cipherTexts: list[bytes]) -> list[bytes]:
    transposedCipherTexts = list(zip(*cipherTexts))

    transposedPlainTexts = [attack_single_byte_key_xor(cipher)[0] for cipher in transposedCipherTexts]
    plainText = list(zip(*transposedPlainTexts))

    return plainText


def main() -> None:
    cipherTexts = get_cipher_and_plain_textes()[:-1]

    plainTexts = do_evil(cipherTexts)
    for text in plainTexts:
        print(bytes(text).decode("utf-8", "ignore"))

main()
