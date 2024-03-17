from base64 import b64decode
from utils import hamming_distance, get_key_size, get_key, create_full_key, bytes_xor

str1 = "this is a test"
str2 = "wokka wokka!!!"
str1 = bytes([ord(x) for x in str1])
str2 = bytes([ord(x) for x in str2])
if (hamming_distance(str1, str2) != 37):
    exit()

f = open("6.txt", "r")
cipher = b64decode(f.read().replace('\n', '').encode())

keySize = get_key_size(cipher)
key = get_key(cipher, keySize)
fullKey = create_full_key(key, len(cipher))

plainText = bytes_xor(fullKey, cipher).decode()

print(plainText)
print("Key size: %d" % keySize)
print("Key.....: %s" % key.decode())




