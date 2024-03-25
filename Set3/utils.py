from Crypto.Cipher import AES


BLOCK_SIZE = AES.block_size

FREQ_TABLE = {
    'a' : 0.08167,
    'b' : 0.01492,
    'c' : 0.02782,
    'd' : 0.04253,
    'e' : 0.1270,
    'f' : 0.02228,
    'g' : 0.02015,
    'h' : 0.06094,
    'i' : 0.06966,
    'j' : 0.00153,
    'k' : 0.00772,
    'l' : 0.04025,
    'm' : 0.02406,
    'n' : 0.06749,
    'o' : 0.07507,
    'p' : 0.01929,
    'q' : 0.00095,
    'r' : 0.05987,
    's' : 0.06327,
    't' : 0.09056,
    'u' : 0.02758,
    'v' : 0.00978,
    'w' : 0.02360,
    'x' : 0.00150,
    'y' : 0.01974,
    'z' : 0.00074
}

def bytes_xor(b1: bytes, b2: bytes) -> bytes:
    return bytes(a^b for (a,b) in zip(b1, b2))

def split_bytes_in_chunks(bt: bytes, size: int) -> list[bytes]:
    return [bt[i:i+size] for i in range(0, len(bt), size)]

def encrypt_AES_CTR(plainText: bytes, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
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
    return encrypt_AES_CTR(cipherText, key, nonce, counter)


