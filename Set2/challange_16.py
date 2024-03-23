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
        data = data
        plainText = prefix + data + postfix
        return encrypt_AES_CBC(pad_pkcs7(plainText), key, iv)

    def decrypt(data: bytes) -> bytes:
        return strip_padding_pkcs7(decrypt_AES_CBC(data, key, iv))

    return (encrypt, decrypt)

def check_admin(cipher: bytes, decrypt: Oracle) -> bool:
    plainText = decrypt(cipher)
    return b";admin=true;" in plainText

def set_admin(encrypt: Oracle) -> bytes:
    byte_a = b'A' * BLOCK_SIZE
    cipher_a = encrypt(byte_a*2)

    admin = b';admin=true'.rjust(BLOCK_SIZE, b'A')
    xor = bytes_xor(byte_a, admin)
    adjusteBlock = xor.rjust(BLOCK_SIZE*3, bytes(1)).ljust(len(cipher_a), bytes(1))

    return bytes_xor(cipher_a, adjusteBlock)
    

encrypt, decrypt = make_oracle()

cipher = encrypt(b';admin=true')
evilCipher = set_admin(encrypt)
print(decrypt(evilCipher))
print(check_admin(evilCipher, decrypt))



