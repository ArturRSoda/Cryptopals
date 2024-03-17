from utils import decode_sigle_byte_key_XOR_cipher, str_to_bytes

f = open("4.txt", "r", encoding="utf-8")

bytes_list = [bytes.fromhex(x) for x in f.read().split('\n')]
bytes_list.pop()
arr = [decode_sigle_byte_key_XOR_cipher(x) for x in bytes_list]
arr.sort()

result = arr[0]

print("Cipher....: %s" % result[3].hex())
print("Key.......: %s" % result[1])
print("PlainText.: %s" % result[2])

f.close()

