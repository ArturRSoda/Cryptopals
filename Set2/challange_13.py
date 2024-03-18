from utils import profile_for, encrypt_AES_ECB, decrypt_AES_ECB, parse

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def set_admin_role(email: bytes, key: bytes) -> bytes:
    email2 = email[:10] + pad(b"admin", AES.block_size) + email[10:]

    cipher1 = encrypt_AES_ECB(pad(profile_for(email), AES.block_size), key)
    cipher2 = encrypt_AES_ECB(pad(profile_for(email2), AES.block_size), key)

    return cipher1[:32]+cipher2[16:32]



key = get_random_bytes(16)

email = b"foooo@bar.com"

evilCipher= set_admin_role(email, key)
pt = unpad(decrypt_AES_ECB(evilCipher, key), AES.block_size)

profile = parse(pt)
for k, v in profile.items():
    print("%s -> %s" % (k.decode(), v.decode()))
