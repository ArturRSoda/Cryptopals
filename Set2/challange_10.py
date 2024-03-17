from utils import decrypt_AES_CBC
from base64 import b64decode

from Crypto.Cipher import AES

f = open("10.txt", "r")
cipher = b64decode(f.read().replace("\n", "").encode())
f.close()

key = bytes(ord(x) for x in "YELLOW SUBMARINE")
iv = b'\x00'*16

p = decrypt_AES_CBC(cipher, key, iv)
print(p.decode())



