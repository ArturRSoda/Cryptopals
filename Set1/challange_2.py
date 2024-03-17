from utils import bytes_xor

input1 = "1c0111001f010100061a024b53535009181c"
input2 = "686974207468652062756c6c277320657965"

expected = "746865206b696420646f6e277420706c6179"

input1 = bytes.fromhex(input1)
input2 = bytes.fromhex(input2)

output = bytes_xor(input1, input2).hex()

print(output if (output == expected) else "fail")
