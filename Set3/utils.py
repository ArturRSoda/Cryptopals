from Crypto.Cipher import AES


BLOCK_SIZE = AES.block_size
ASCII_TEXT_CHARS = list(range(97, 122)) + [32]

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


class MT19937:
    def __init__(self, version: int, seed: int):
        assert version in (32, 64)
        self.version = version

        if (self.version == 32):
            self.w = 32;         self.n = 624
            self.m = 397;        self.r = 31
            self.a = 0x9908B0DF; self.u = 11
            self.d = 0xFFFFFFFF; self.s = 7
            self.b = 0x9D2C5680; self.t = 15
            self.c = 0xEFC60000; self.l = 18
            self.f = 181243325
        else:
            self.w = 64;                 self.n = 312
            self.m = 156;                self.r = 31
            self.a = 0xB5026F5AA96619E9; self.u = 29
            self.d = 0x5555555555555555; self.s = 17
            self.b = 0x71D67FFFEDA60000; self.t = 37
            self.c = 0xFFF7EEE000000000; self.l = 43
            self.f = 636413622384679300

        self.lower_mask = 0x7FFFFFFF
        self.upper_mask = ~((1 << self.w) + self.lower_mask)
            
        self.MT = [i for i in range(self.n)]
        self.index = self.n + 1
        self.seed_mt(seed)

    def seed_mt(self, seed: int):
        self.index = self.n
        self.MT[0] = seed
        for i in range(1, self.n):
            self.MT[i] = (self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i) & ((1 << self.w) - 1)
 
    def genrand_int(self) -> int:
        if self.index >= self.n:
            self._twist()
 
        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
     
        self.index += 1

        return y & ((1 << self.w) - 1)

    def get_state(self) -> list[int]:
        return self.MT

    def set_state(self, state: list[int]):
        if (len(state) != self.n):
            raise ValueError(f"State needs to be of size {self.n}")
        self.index = self.n
        self.MT = state

    def _twist(self):
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ self.a
            
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
    
        self.index = 0



def bytes_xor(b1: bytes, b2: bytes) -> bytes:
    return bytes(a^b for (a,b) in zip(b1, b2))

def split_bytes_in_chunks(bt: bytes, size: int) -> list[bytes]:
    return [bt[i:i+size] for i in range(0, len(bt), size)]

def attack_single_byte_key_xor(cipher: bytes) -> tuple[bytes, bytes]:
    bestPlainText = b""
    bestNLetter = 0
    bestKeyStream = b""

    for i in range(256):
        keyStream = bytes([i])*len(cipher)
        plainTextGuessed = bytes_xor(cipher, keyStream)
        nLetter = sum([ x in ASCII_TEXT_CHARS for x in plainTextGuessed])
        if (nLetter > bestNLetter):
            bestPlainText = plainTextGuessed
            bestNLetter = nLetter
            bestKeyStream = keyStream

    return (bestPlainText, bestKeyStream)

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


