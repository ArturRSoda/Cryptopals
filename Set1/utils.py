from base64 import b64encode
from Crypto.Cipher import AES

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

def hex_to_b64(b_hex: bytes) -> bytes:
    return b64encode(b_hex)

def bytes_xor(b1: bytes, b2: bytes) -> bytes:
    return bytes(a^b for (a,b) in zip(b1, b2))

def str_to_bytes(string: str) -> bytes:
    return bytes([ord(x) for x in string])

def single_byte_xor(byte: int, text: bytes) -> bytes:
    return bytes(byte^x for x in text)

def create_full_key(key: str, l: int) -> str:
    return key*(l//len(key)) + key[:(l%len(key))]

def hamming_distance(a: bytes, b: bytes) -> int:
    return sum([bin(b1^b2).count('1') for b1, b2 in zip(a, b)])

def decrypt_AES_ECB(cipher: bytes, key:bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(cipher)

def get_score_text(text: str) -> float:
    text.lower()

    t = len(text)
    score = 0
    for char, freq in FREQ_TABLE.items():
        textCharFreq = text.count(char)/t
        score += abs(freq - textCharFreq)
    
    return score

def decode_sigle_byte_key_XOR_cipher(cipher: bytes) -> tuple:

    #128 -> qtd de caracteres tabela ascii
    scores = list()
    for i in range(128):
        bytesPlainText = bytes([i^b for b in cipher])
        plainText = bytesPlainText.decode("utf-8", "ignore")
        score = get_score_text(plainText)
        scores.append((score, chr(i), plainText, cipher))

    scores.sort()
    return scores[0]

def get_key(cipher: bytes, keySize: int) -> bytes:
    key = b''

    for i in range(keySize):
        block = cipher[i:-1:keySize]
        key += decode_sigle_byte_key_XOR_cipher(block)[1].encode()

    return key

def get_key_size(cipher: bytes) -> int:
    m = 2
    max = 40
    distances = [hamming_distance(cipher[-i:] + cipher[:-i], cipher) for i in range(max+1)]

    return distances.index(min(distances[m:]))



