from utils import split_bytes_in_chunks, bytes_xor
from base64 import b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = AES.block_size

def encryp_AES_CTR(plainText: bytes, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    if (not isinstance(counter, int)):
        raise Exception("Error: counter must be integer")

    if (len(nonce) != BLOCK_SIZE//2):
        raise Exception("Error: nonce size must be blockSize/2")

    plainTextBlocks = split_bytes_in_chunks(plainText, BLOCK_SIZE)    
    cipher = b""
    for block in plainTextBlocks:
        keyStream = nonce + counter.to_bytes(BLOCK_SIZE//2, "little")
        enc = AES.new(key, AES.MODE_ECB).encrypt(keyStream)
        counter += 1

        cipher += bytes_xor(enc, block)

    return cipher

def decrypt_AES_CTR(cipherText: bytes, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    return encryp_AES_CTR(cipherText, key, nonce, counter)

def main() -> None:
    b64Cipher = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    cipher = b64decode(b64Cipher)

    key = b"YELLOW SUBMARINE"
    nonce = bytes(BLOCK_SIZE//2)

    plainText = encryp_AES_CTR(cipher, key, nonce)
    print(plainText)

    print("()")
    print("===================>")
    print("()")

    plainText = B"el psy congro"
    key = get_random_bytes(BLOCK_SIZE)
    nonce = get_random_bytes(BLOCK_SIZE//2)
    cipher = encryp_AES_CTR(plainText, key, nonce, 2398749283749)
    print(cipher)
    pt = decrypt_AES_CTR(cipher, key, nonce, 2398749283749)
    print(pt)


main()
