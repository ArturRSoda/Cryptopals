from utils import profile_for, encrypt_AES_ECB, decrypt_AES_ECB, parse, cut_and_past_atack

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def oracle(text: bytes, key: bytes, enc_dec: str) -> bytes:
    if enc_dec == "ENC":
        return encrypt_AES_ECB(pad(profile_for(text), AES.block_size), key)
    else:
        return unpad(decrypt_AES_ECB(text, key), AES.block_size)


key = get_random_bytes(16)

email = b"emailde13digi"

pt = cut_and_past_atack(email, oracle, key)

profile = parse(pt)
for k, v in profile.items():
    print("%s -> %s" % (k.decode(), v.decode()))
