from utils import encrypt_AES_CTR, FREQ_TABLE, bytes_xor
from base64 import b64decode

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

BLOCK_SIZE = AES.block_size


def get_cipher_and_plain_textes() -> tuple[list[bytes], list[bytes]]:
    f = open("19.txt", "r")
    plainText = [b64decode(line) for line in f.read().split('\n')]
    f.close()

    key = get_random_bytes(BLOCK_SIZE)
    nonce = get_random_bytes(BLOCK_SIZE//2)
    cipher = [encrypt_AES_CTR(pt, key, nonce) for pt in plainText]

    return plainText, cipher

def set_equal_length_ciphers(ciphers: list[bytes]) -> list[bytes]:
    return [cipher + bytes(max([len(x) for x in ciphers]) - len(cipher)) for cipher in ciphers]

def get_score_text(text: str) -> float:
    text.lower()

    t = len(text)
    score = 0
    for char, freq in FREQ_TABLE.items():
        textCharFreq = text.count(char)/t
        score += abs(freq - textCharFreq)
    
    return score

def do_evil(plainTexts: list[bytes], cipherTexts: list[bytes]):
    keyStream = b""
    longesCipher = cipherTexts[[len(x) for x in cipherTexts].index(max([len(x) for x in cipherTexts]))]

    text = b""
    for i in range(len(longesCipher)):
        for j in range(len(plainTexts)):
            xor = longesCipher[i]^plainTexts[j][i]




def main() -> None:
    plainTexts, cipherTexts = get_cipher_and_plain_textes()

    do_evil(plainTexts, cipherTexts)

main()
