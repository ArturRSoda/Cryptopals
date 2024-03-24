def bytes_xor(b1: bytes, b2: bytes) -> bytes:
    return bytes(a^b for (a,b) in zip(b1, b2))

def split_bytes_in_chunks(bt: bytes, size: int) -> list[bytes]:
    return [bt[i:i+size] for i in range(0, len(bt), size)]

