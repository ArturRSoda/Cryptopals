from utils import decode_sigle_byte_key_XOR_cipher

input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
input = bytes.fromhex(input)
r = decode_sigle_byte_key_XOR_cipher(input)
print("key.......: %s" % r[1])
print("PlainText.: %s " % r[2])

