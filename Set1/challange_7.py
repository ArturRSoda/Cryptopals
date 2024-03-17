from base64 import b64decode

from utils import decrypt_AES_ECB

f = open("7.txt", "r")
cipher = b64decode(f.read().replace('\n', "").encode())
f.close()

key = bytes(ord(x) for x in "YELLOW SUBMARINE")

plainText = decrypt_AES_ECB(cipher, key).decode()
print(plainText)
