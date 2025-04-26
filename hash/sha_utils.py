# hash/sha_utils.py

import hashlib

def shake256_hash(data: bytes, digest_len: int = 64) -> str:
    shake = hashlib.shake_256()
    shake.update(data)
    return shake.hexdigest(digest_len)

def sha3_512_hash(data: bytes) -> str:
    return hashlib.sha3_512(data).hexdigest()
