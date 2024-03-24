from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from random import randint
from typing import Callable
    
OracleChall12 = Callable[[bytes], bytes]
OracleChall13 = Callable[[bytes, bytes, str], bytes]

def bytes_xor(b1: bytes, b2: bytes) -> bytes:
    return bytes(a^b for (a,b) in zip(b1, b2))

def split_bytes_in_chunks(bt: bytes, size: int) -> list[bytes]:
    return [bt[i:i+size] for i in range(0, len(bt), size)]

def encrypt_AES_ECB(cipher: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(cipher)

def decrypt_AES_ECB(cipher: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(cipher)

def encrypt_AES_CBC(cipher: bytes, key: bytes, iv: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(cipher)

def pad_pkcs7(byteText: bytes, blockSize: int = AES.block_size) -> bytes:
    return pad(byteText, blockSize)

def unpad_pkcs7(byteText: bytes, blockSize: int = AES.block_size) -> bytes:
    return unpad(byteText, blockSize)

def strip_padding_pkcs7(byteText: bytes, blockSize: int = AES.block_size) -> bytes:
    if ((len(byteText) % blockSize) != 0):
        raise Exception("Error: Bad Padding")

    p = byteText[-1]
    for _ in range(p-1):
        if ((p != byteText[-2]) or (p == 0)):
            raise Exception("Error: Bad Padding")
        else:
            byteText = byteText[:-1]
            p = byteText[-1]

    byteText = byteText[:-1]
    return byteText

    

def decrypt_AES_CBC(cipher: bytes, key: bytes, iv: bytes) -> bytes:
    cipherChunks = split_bytes_in_chunks(cipher, AES.block_size)
    prev = iv
    plainTextBytes = b''
    for chunk in cipherChunks:
        d = decrypt_AES_ECB(chunk, key)
        plainTextBytes += bytes_xor(prev, d)
        prev = chunk
    return plainTextBytes

        
def encryption_oracle(plainText: bytes) -> tuple[bytes, str]:
    mode = ("ECB","CBC")[randint(0, 1)]

    key = get_random_bytes(16)
    prefix = get_random_bytes(randint(5, 10))
    postfix = get_random_bytes(randint(5, 10))
    padText = pad(prefix+plainText+postfix, 16)

    if (mode == "ECB"):
        return (encrypt_AES_ECB(padText, key), mode)
    else:
        iv = get_random_bytes(16)
        return (encrypt_AES_CBC(padText, key, iv), mode)

def detect_ECB_CBC(cipher: bytes, blockSize: int) -> str:
    cipherChunks = split_bytes_in_chunks(cipher, blockSize)
    return "ECB" if (cipherChunks[1] == cipherChunks[2]) else "CBC"

def guess_blockSize_postfixSize(oracle: OracleChall12) -> tuple[int, int]:
    blockSize = -1
    postfixSize = -1

    l = len(oracle(b'A'))
    i = 2
    while True:
        l2 = len(oracle(b'A' * i))

        if (l2 > l):
            blockSize = l2 - l
            postfixSize = l - i
            break

        i += 1

    return (blockSize, postfixSize)

def detect_if_ECB(oracle: OracleChall12, blockSize: int) -> bool:
    cipher = oracle(bytes(blockSize*2))
    return True if (cipher[:blockSize] == cipher[blockSize:blockSize*2]) else False

def decrypt_byte(prefix: bytes, block: bytes, oracle: OracleChall12, blockSize: int) -> bytes:
    b = None

    for b in range(256):
        b = bytes([b])
        cipher = prefix + b
        if (oracle(cipher)[:blockSize] == block):
            break

    assert b is not None
    return b

def make_codebook(prefix: bytes, oracle: OracleChall12, blockSize: int, block: int) -> dict[bytes, bytes]:                
    codebook = {}
    for b in range(256):

        byte = bytes([b])
        cipher = prefix+byte
        secondBlock = oracle(cipher)[blockSize*block:(blockSize*block)+blockSize]
        codebook[secondBlock] = byte

    return codebook

def discover_postfix(prefix: bytes, cipherBlocks: list[list[bytes]], oracle: OracleChall12, blockSize: int, postfixSize: int, blockToCheck: int) -> bytes:

    postfix = b''
    nCipher = 0
    nBlock = blockToCheck

    while (len(postfix) < postfixSize):

        block = cipherBlocks[nCipher][nBlock]
        codebook = make_codebook(prefix, oracle, blockSize, blockToCheck)
        prefix = prefix[1:] + codebook[block]
        postfix += codebook[block]

        nCipher += 1
        if (nCipher >= len(cipherBlocks)):
            nCipher = 0

            nBlock += 1
            if (nBlock >= len(cipherBlocks[nCipher])):
                nBlock = blockToCheck

    return postfix


def parse(profile: bytes) -> dict[bytes, bytes]:
    return {key : value for key, value in [pair.split(b"=") for pair in profile.split(b"&")]}

def profile_for(email: bytes) -> bytes:
    return b"email=%s&uid=10&role=user" % email.translate(None, b"&=")

def cut_and_past_atack(email: bytes, oracle: OracleChall13, key: bytes) -> bytes:
    evilEmail = email[:10] + pad(b"admin", AES.block_size) + email[10:]

    cipherOrig = oracle(email, key, "ENC")
    adminCipher = oracle(evilEmail, key, "ENC")

    evilCipher = cipherOrig[:32] + adminCipher[16:32]

    return oracle(evilCipher, key, "DEC")



