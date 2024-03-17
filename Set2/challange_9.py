from Crypto.Util.Padding import pad

input = bytes(ord(x) for x in "YELLOW SUBMARINE")
expected = b"YELLOW SUBMARINE\x04\x04\x04\x04"
output = pad(input, 20, 'pkcs7')

print(output if (output == expected) else "fail")

