from utils import encrypt_AES_ECB, guess_blockSize_postfixSize, discover_postfix, decrypt_AES_ECB, split_bytes_in_chunks
from typing import Callable
from base64 import b64decode
from random import randint
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

Oracle = Callable[[bytes], bytes]

#
KEY = None

def make_oracle() -> tuple:
    key = get_random_bytes(16)
    prefix = get_random_bytes(randint(1, 15))
    postfix = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

    def oracle(plainText: bytes) -> bytes:
        return encrypt_AES_ECB(pad(prefix+plainText+postfix, AES.block_size), key)

    def simpleDecrypt(cipher: bytes) -> bytes:
        return decrypt_AES_ECB(cipher, key)

    return oracle, simpleDecrypt

def discover_midle_text(oracle: Oracle) -> bytes:
    midleText = b""
    prevFirstBlock = b""
    while True:
        firstBlock = oracle(midleText)[:16]

        if (firstBlock == prevFirstBlock):
            break

        midleText += b"A"
        prevFirstBlock = firstBlock

    return midleText[:-2]


oracle, decrypt = make_oracle()

midleTextLen = len(discover_midle_text(oracle))

blockSize, postfixSize = guess_blockSize_postfixSize(oracle)
postfixSize -= blockSize-midleTextLen

midleText = bytes(midleTextLen+blockSize)
cipherBlocks = [split_bytes_in_chunks(oracle(bytes(midleTextLen+blockSize-n)), blockSize) for n in range(blockSize)]

postfix = discover_postfix(midleText, cipherBlocks, oracle, blockSize, postfixSize, 1)
print(postfix.decode())
