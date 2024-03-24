from utils import decrypt_AES_CBC, pad_pkcs7, encrypt_AES_CBC, strip_padding_pkcs7, bytes_xor

from typing import Callable

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

Oracle = Callable[[bytes], bytes]
BLOCK_SIZE = AES.block_size

def make_oracle() -> tuple:
    key = get_random_bytes(BLOCK_SIZE)
    iv = get_random_bytes(BLOCK_SIZE)

    prefix = b"comment1=cooking%20MCs;userdata="
    postfix = b";comment2=%20like%20a%20pound%20of%20bacon"

    def encrypt(data: bytes) -> bytes:
        return encrypt_AES_CBC(pad_pkcs7(prefix+data.replace(b";", b"").replace(b"=", b"")+postfix), key, iv)

    def decrypt(cipher: bytes) -> bytes:
        return strip_padding_pkcs7(decrypt_AES_CBC(cipher, key, iv))

    return encrypt, decrypt
    
def check_admin(cipher: bytes, decrypt: Oracle) -> bool:
    return (b";admin=true;" in decrypt(cipher))

def set_admin(encrypt: Oracle) -> bytes:
    a_bytes = b'A' * BLOCK_SIZE
    cipher = encrypt(a_bytes*2)

    xorBlock = bytes_xor(a_bytes, b";admin=true".rjust(BLOCK_SIZE, bytes(1))).rjust(BLOCK_SIZE*3, bytes(1)).ljust(len(cipher), bytes(1))

    return bytes_xor(cipher, xorBlock)


encrypt, decrypt = make_oracle()
evilCipher = set_admin(encrypt)
print(check_admin(evilCipher, decrypt))

