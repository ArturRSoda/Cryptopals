from utils import strip_padding_pkcs7

input1 = b"ICE ICE BABY\x04\x04\x04\x04"
print(strip_padding_pkcs7(input1))
print("input1 validado")

try:
    input2 = b"ICE ICE BABY\x05\x05\x05\x05"
    strip_padding_pkcs7(input2)
except Exception as e:
    print(e)

try:
    input3 = b"ICE ICE BABY\x01\x02\x03\x04"
    strip_padding_pkcs7(input3)
except Exception as e:
    print(e)
