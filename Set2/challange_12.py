from utils import guess_blockSize_postfixSize, detect_if_ECB, split_bytes_in_chunks, decrypt_AES_ECB, make_codebook, discover_postfix
from typing import Callable
from Crypto.Random import get_random_bytes
from base64 import b64decode
from Crypto.Util.Padding import pad

Oracle = Callable[[bytes], bytes]

def make_oracle() -> Oracle:
    key = get_random_bytes(16)
    postfix = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

    def oracle(plainText: bytes) -> bytes:
        return decrypt_AES_ECB(pad(plainText+postfix, 16), key)

    return oracle

oracle = make_oracle()
blockSize, postfixSize = guess_blockSize_postfixSize(oracle)

if (not detect_if_ECB(oracle, blockSize)):
    exit()


prefix = bytes(blockSize-1)
cipherBlocks = [split_bytes_in_chunks(oracle(prefix[:blockSize-1-n]), blockSize) for n in range(blockSize)]

postfix = discover_postfix(prefix, cipherBlocks, oracle, blockSize, postfixSize, 0)

print(postfix.decode())

