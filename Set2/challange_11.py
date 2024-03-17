from utils import encryption_oracle, detect_ECB_CBC
from Crypto.Cipher import AES

plainText = bytes(3*AES.block_size)
cipher, expectedMode = encryption_oracle(plainText)

mode = detect_ECB_CBC(cipher, AES.block_size)

print(mode if (mode == expectedMode) else "fail")



