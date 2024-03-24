from utils import bytes_xor, split_bytes_in_chunks

from random import choice
from typing import Callable
from base64 import b64decode

from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

TryDecrypt = Callable[[bytes, bytes], bool]

BLOCK_SIZE = AES.block_size

def make_oracle():
    key = get_random_bytes(BLOCK_SIZE)
    iv = get_random_bytes(BLOCK_SIZE)

    plainText = b64decode(choice([
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ]))

    def cipherText() -> bytes:
        return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plainText, BLOCK_SIZE))

    def try_decrypt(cipher: bytes, iv: bytes) -> bool:
        try:
            unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher), BLOCK_SIZE)
        except:
            return False
        else:
            return True

    return iv, cipherText(), try_decrypt, plainText


def discover_byte(cipherBlock: bytes, breakIv: bytes, index: int, try_decrypt: TryDecrypt) -> tuple[bytes, bytes]: 
    for b in range(256):
        breakIv = breakIv[:-index] + bytes([b]) + breakIv[-index+1:] if (index > 1) else breakIv[:-index] + bytes([b])
        if (try_decrypt(cipherBlock, breakIv)):
            return (breakIv, bytes([b]))
    else:
        raise Exception("oh oh :(")


def break_single_block(cipherBlock: bytes, try_decrypt: TryDecrypt) -> bytes:
    breakIv = bytes(BLOCK_SIZE)
    ivKey = b""
    zeroingIv = b""
    for i in range(1, BLOCK_SIZE+1):
        breakIv, byte = discover_byte(cipherBlock, breakIv, i, try_decrypt)
        zeroingIv = bytes_xor(byte, bytes([i])) + zeroingIv

        cipherByte = cipherBlock[-i:-i+1] if (i > 1) else cipherBlock[-i:]
        breakIvByte = breakIv[-i:-i+1] if (i > 1) else breakIv[-i:]
        p = bytes_xor(bytes([i]), bytes_xor(cipherByte, breakIvByte))

        ivKey = p + ivKey

        breakIv =  bytes_xor(cipherBlock[-i:], bytes_xor(ivKey, bytes([i+1])*i)).rjust(BLOCK_SIZE, b"\x00")

    return zeroingIv

def break_cbc(cipher: bytes, iv: bytes, try_decrypt: TryDecrypt) -> bytes:
    cipherBlocks = split_bytes_in_chunks(cipher, BLOCK_SIZE)
    plainText = b""
    prev = iv
    for block in cipherBlocks:
        plainText += bytes_xor(prev, break_single_block(block, try_decrypt))
        prev = block
    return plainText
        
def main():
    iv, cipher, try_decrypt, plainText = make_oracle()
    plainText = break_cbc(cipher, iv, try_decrypt)
    print(unpad(plainText, BLOCK_SIZE))
    

main()
