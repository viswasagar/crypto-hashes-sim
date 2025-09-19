# advanced_simulation_scratch.py (FIXED & OPTIMIZED FOR PYTHON)
#
# A "from scratch" Python implementation of the advanced cryptographic simulation.
# This script contains pure Python implementations for:
# - Shamir's Secret Sharing on a large prime field
# - Merkle tree build and verification
# - AES-256 block cipher and AES-256-GCM mode of operation
# - RSA key generation and PSS (SHA-256) sign/verify
# - HMAC-SHA256, SHA-256
# - "BLAKE3-like" hashing function (toy)
# - "Argon2-like" password hashing (toy)
#
# All cryptographic functions are implemented without external crypto libraries
# to match the structure of the original Java file.
#
# DISCLAIMER:
# This code is for educational purposes ONLY. These from-scratch implementations
# are NOT secure, not optimized, and not hardened against attacks.
# DO NOT USE IN PRODUCTION.

import argparse
import os
import sys
import struct
import math
import secrets
from datetime import datetime, timezone
from pymongo import MongoClient

# ------------------------------------------------------------------------------
# CONFIGURATION & SETUP
# ------------------------------------------------------------------------------

# Crypto parameters
AES_KEY_SIZE_BYTES = 32
HMAC_KEY_SIZE_BYTES = 32
RSA_KEY_SIZE_BITS = 2048 # Note: Key generation from scratch will be slow

# Simulation parameters defaults
DEFAULT_NUM_USERS = 100
DEFAULT_SHARES = 5
DEFAULT_THRESHOLD = 3

# Big prime > 2^256
PRIME = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "crypto_simulation_py_scratch"


# ------------------------------------------------------------------------------
# HELPER CLASSES & FUNCTIONS
# ------------------------------------------------------------------------------

class Logger:
    @staticmethod
    def _ts():
        return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    @staticmethod
    def info(s):
        print(f"{Logger._ts()} [INFO] {s}")

    @staticmethod
    def warn(s):
        print(f"{Logger._ts()} [WARN] {s}")

    @staticmethod
    def error(s):
        print(f"{Logger._ts()} [ERROR] {s}", file=sys.stderr)

class Hex:
    @staticmethod
    def to_hex(b: bytes) -> str:
        return b.hex()

    @staticmethod
    def from_hex(s: str) -> bytes:
        return bytes.fromhex(s)

def random_bytes(n: int) -> bytes:
    return os.urandom(n)

def concat(*arrays: bytes) -> bytes:
    return b''.join(arrays)

def pick_random_punctuation() -> str:
    punct = "!@#$%^&*()_+-=[]{}|;:',.<>?/"
    return punct[secrets.randbelow(len(punct))]

def pick_random_distinct_ints(upper_exclusive: int, count: int) -> list[int]:
    import random
    population = range(upper_exclusive)
    return random.sample(population, min(count, len(population)))

def big_int_to_fixed_bytes(n: int, length: int) -> bytes:
    if n.bit_length() > length * 8:
        raise ValueError(f"Integer {n} is too large to fit in {length} bytes")
    return n.to_bytes(length, 'big')

def bytes_to_big_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# ------------------------------------------------------------------------------
# SHA-256 from scratch (FIPS 180-4)
# ------------------------------------------------------------------------------
class SHA256:
    _K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    _H_init = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    @staticmethod
    def _rotr(x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def digest(message: bytes) -> bytes:
        # FIX 1: Ensure input is an immutable bytes object to handle bytearray inputs
        message = bytes(message)

        h = list(SHA256._H_init)
        ml = len(message) * 8
        message += b'\x80'
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'
        message += struct.pack('>Q', ml)

        for i in range(0, len(message), 64):
            chunk = message[i:i + 64]
            w = list(struct.unpack('>16L', chunk))

            for t in range(16, 64):
                s0 = SHA256._rotr(w[t-15], 7) ^ SHA256._rotr(w[t-15], 18) ^ (w[t-15] >> 3)
                s1 = SHA256._rotr(w[t-2], 17) ^ SHA256._rotr(w[t-2], 19) ^ (w[t-2] >> 10)
                w.append((w[t-16] + s0 + w[t-7] + s1) & 0xFFFFFFFF)

            a, b, c, d, e, f, g, h0 = h

            for t in range(64):
                s1 = SHA256._rotr(e, 6) ^ SHA256._rotr(e, 11) ^ SHA256._rotr(e, 25)
                ch = (e & f) ^ (~e & g)
                temp1 = (h0 + s1 + ch + SHA256._K[t] + w[t]) & 0xFFFFFFFF
                s0 = SHA256._rotr(a, 2) ^ SHA256._rotr(a, 13) ^ SHA256._rotr(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (s0 + maj) & 0xFFFFFFFF

                h0 = g; g = f; f = e; e = (d + temp1) & 0xFFFFFFFF
                d = c; c = b; b = a; a = (temp1 + temp2) & 0xFFFFFFFF

            h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, h0])]

        return b''.join(x.to_bytes(4, 'big') for x in h)

# ------------------------------------------------------------------------------
# HMAC-SHA256 from scratch
# ------------------------------------------------------------------------------
class HMAC:
    @staticmethod
    def hmac_sha256(key: bytes, message: bytes) -> bytes:
        block_size = 64
        if len(key) > block_size:
            key = SHA256.digest(key)
        if len(key) < block_size:
            key += b'\x00' * (block_size - len(key))

        o_key_pad = bytes(x ^ 0x5c for x in key)
        i_key_pad = bytes(x ^ 0x36 for x in key)

        inner = SHA256.digest(i_key_pad + message)
        return SHA256.digest(o_key_pad + inner)

# ------------------------------------------------------------------------------
# AES-256 block cipher from scratch
# ------------------------------------------------------------------------------
class AES:
    _S_BOX = bytes.fromhex(
        "637c777bf26b6fC53001672bfed7ab76"
        "ca82c97dfa5947f0add4a2af9ca472c0"
        "b7fd9326363ff7cc34a5e5f171d83115"
        "04c723c31896059a071280e2eb27b275"
        "09832c1a1b6e5aa0523bd6b329e32f84"
        "53d100ed20fcb15b6acbbe394a4c58cf"
        "d0efaafb434d338545f9027f503c9fa8"
        "51a3408f929d38f5bcb6da2110fff3d2"
        "cd0c13ec5f974417c4a77e3d645d1973"
        "60814fdc222a908846eeb814de5e0bdb"
        "e0323a0a4906245cc2d3ac629195e479"
        "e7c8376d8dd54ea96c56f4ea657aae08"
        "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
        "703eb5664803f60e613557b986c11d9e"
        "e1f8981169d98e949b1e87e9ce5528df"
        "8ca1890d bfe6426841992d0fb054bb16"
    )
    _RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        self._Nr = 14
        self._round_keys = self._key_expansion(key)

    def _sub_word(self, word: list[int]) -> list[int]:
        return [self._S_BOX[b] for b in word]

    def _rot_word(self, word: list[int]) -> list[int]:
        return word[1:] + word[:1]

    def _key_expansion(self, key: bytes) -> list[list[list[int]]]:
        key_words = [list(key[i:i+4]) for i in range(0, 32, 4)]

        for i in range(8, 4 * (self._Nr + 1)):
            temp = list(key_words[i-1]) # Make a copy
            if i % 8 == 0:
                temp = self._rot_word(temp)
                temp = self._sub_word(temp)
                rcon_byte = self._RCON[i//8]
                temp[0] ^= rcon_byte
            elif i % 8 == 4:
                temp = self._sub_word(temp)

            new_word = [temp[j] ^ key_words[i-8][j] for j in range(4)]
            key_words.append(new_word)

        return [[key_words[r * 4 + c] for c in range(4)] for r in range(self._Nr + 1)]

    def _add_round_key(self, state: list[list[int]], round_num: int):
        for c in range(4):
            for r in range(4):
                state[r][c] ^= self._round_keys[round_num][c][r]

    def _sub_bytes(self, state: list[list[int]]):
        for r in range(4):
            for c in range(4):
                state[r][c] = self._S_BOX[state[r][c]]

    def _shift_rows(self, state: list[list[int]]):
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]

    def _xtime(self, a: int) -> int:
        return ((a << 1) ^ 0x1B if (a & 0x80) else (a << 1)) & 0xFF

    def _mix_columns(self, state: list[list[int]]):
        for c in range(4):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
            state[0][c] = self._xtime(s0) ^ (self._xtime(s1) ^ s1) ^ s2 ^ s3
            state[1][c] = s0 ^ self._xtime(s1) ^ (self._xtime(s2) ^ s2) ^ s3
            state[2][c] = s0 ^ s1 ^ self._xtime(s2) ^ (self._xtime(s3) ^ s3)
            state[3][c] = (self._xtime(s0) ^ s0) ^ s1 ^ s2 ^ self._xtime(s3)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        state = [list(plaintext[i:i+4]) for i in range(0, 16, 4)]
        # Transpose to column-major order for easier state manipulation
        state = [[state[r][c] for r in range(4)] for c in range(4)]

        self._add_round_key(state, 0)
        for r_num in range(1, self._Nr):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, r_num)

        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self._Nr)

        # Transpose back and flatten
        output = bytearray(16)
        for c in range(4):
            for r in range(4):
                output[c*4 + r] = state[r][c]
        return bytes(output)

# ------------------------------------------------------------------------------
# AES-256-GCM from scratch
# ------------------------------------------------------------------------------
class AESGCM:
    @staticmethod
    def _gf_mult(x: bytes, y: bytes) -> bytes:
        # Multiplication in GF(2^128) with GCM polynomial
        R = 0xE1000000000000000000000000000000
        z = 0
        v = int.from_bytes(y, 'big')
        x_int = int.from_bytes(x, 'big')

        for i in range(127, -1, -1):
            if (x_int >> i) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ R
            else:
                v = v >> 1
        return z.to_bytes(16, 'big')

    @staticmethod
    def _ghash(h: bytes, aad: bytes, c: bytes) -> bytes:
        # Pad AAD and Ciphertext to 16-byte blocks
        padded_aad = aad + b'\x00' * ((16 - len(aad) % 16) % 16)
        padded_c = c + b'\x00' * ((16 - len(c) % 16) % 16)

        y = b'\x00' * 16
        for i in range(0, len(padded_aad), 16):
            block = padded_aad[i:i+16]
            y = AESGCM._gf_mult(xor_bytes(y, block), h)

        for i in range(0, len(padded_c), 16):
            block = padded_c[i:i+16]
            y = AESGCM._gf_mult(xor_bytes(y, block), h)

        len_block = (len(aad) * 8).to_bytes(8, 'big') + (len(c) * 8).to_bytes(8, 'big')
        y = AESGCM._gf_mult(xor_bytes(y, len_block), h)
        return y

    @staticmethod
    def _inc32(block: bytes) -> bytes:
        val = int.from_bytes(block[12:16], 'big')
        new_val = (val + 1) & 0xFFFFFFFF
        return block[:12] + new_val.to_bytes(4, 'big')

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> dict:
        nonce = random_bytes(12)
        aes = AES(key)

        h = aes.encrypt_block(b'\x00' * 16)
        j0 = nonce + b'\x00\x00\x00\x01'

        ciphertext = b''
        ctr = AESGCM._inc32(j0)

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            encrypted_ctr = aes.encrypt_block(ctr)
            ciphertext += xor_bytes(block, encrypted_ctr)
            ctr = AESGCM._inc32(ctr)

        tag = AESGCM._ghash(h, associated_data, ciphertext)
        encrypted_j0 = aes.encrypt_block(j0)
        final_tag = xor_bytes(tag, encrypted_j0)

        return {"nonce": nonce, "ciphertext": ciphertext + final_tag}

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes) -> bytes:
        if len(ciphertext_with_tag) < 16:
            raise ValueError("Invalid ciphertext length")

        ciphertext = ciphertext_with_tag[:-16]
        received_tag = ciphertext_with_tag[-16:]

        aes = AES(key)
        h = aes.encrypt_block(b'\x00' * 16)

        # Re-calculate tag
        tag_check = AESGCM._ghash(h, associated_data, ciphertext)
        j0 = nonce + b'\x00\x00\x00\x01'
        encrypted_j0 = aes.encrypt_block(j0)
        expected_tag = xor_bytes(tag_check, encrypted_j0)

        # Constant time comparison
        if not secrets.compare_digest(received_tag, expected_tag):
            raise ValueError("GCM tag mismatch")

        plaintext = b''
        ctr = AESGCM._inc32(j0)
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            encrypted_ctr = aes.encrypt_block(ctr)
            plaintext += xor_bytes(block, encrypted_ctr)
            ctr = AESGCM._inc32(ctr)

        return plaintext

# ------------------------------------------------------------------------------
# RSA with PSS from scratch
# ------------------------------------------------------------------------------
class RSA:
    def __init__(self, n=None, e=None, d=None):
        self.n = n
        self.e = e
        self.d = d

    @staticmethod
    def _is_prime_miller_rabin(n, k=40):
        if n < 2: return False
        if n == 2 or n == 3: return True
        if n % 2 == 0 or n % 3 == 0: return False
        d, s = n - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def _get_prime(bits):
        while True:
            p = secrets.randbits(bits)
            p |= (1 << bits - 1) | 1 # Ensure it has 'bits' length and is odd
            if RSA._is_prime_miller_rabin(p):
                return p

    @staticmethod
    def _extended_gcd(a, b):
        if a == 0: return b, 0, 1
        gcd, x1, y1 = RSA._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    @staticmethod
    def _mod_inverse(a, m):
        gcd, x, y = RSA._extended_gcd(a, m)
        if gcd != 1: raise Exception('Modular inverse does not exist')
        return x % m

    @classmethod
    def generate(cls, bits):
        Logger.info(f"Generating {bits}-bit RSA keys... (this may take a moment)")
        e = 65537
        while True:
            p = cls._get_prime(bits // 2)
            q = cls._get_prime(bits // 2)
            if p == q: continue

            n = p * q
            phi = (p - 1) * (q - 1)

            if math.gcd(e, phi) == 1:
                d = cls._mod_inverse(e, phi)
                Logger.info("RSA key generation complete.")
                return cls(n, e, d)

    @staticmethod
    def _mgf1(seed: bytes, length: int) -> bytes:
        h_len = 32 # SHA256 output length
        mask = b''
        counter = 0
        while len(mask) < length:
            c_bytes = counter.to_bytes(4, 'big')
            mask += SHA256.digest(seed + c_bytes)
            counter += 1
        return mask[:length]

    def sign_pss(self, message: bytes) -> bytes:
        h_len = 32
        s_len = 32
        em_bits = self.n.bit_length() - 1
        em_len = math.ceil(em_bits / 8)

        if em_len < h_len + s_len + 2:
            raise ValueError("Encoding error: key too small")

        m_hash = SHA256.digest(message)
        salt = random_bytes(s_len)

        m_prime = b'\x00' * 8 + m_hash + salt
        h = SHA256.digest(m_prime)

        ps_len = em_len - s_len - h_len - 2
        ps = b'\x00' * ps_len

        db = ps + b'\x01' + salt
        db_mask = self._mgf1(h, len(db))
        masked_db = xor_bytes(db, db_mask)

        # Clear leading bits
        mask = 0xFF >> (8 * em_len - em_bits)
        masked_db = bytes([masked_db[0] & mask]) + masked_db[1:]

        em = masked_db + h + b'\xbc'

        m = bytes_to_big_int(em)
        s = pow(m, self.d, self.n)

        return big_int_to_fixed_bytes(s, em_len)

    def verify_pss(self, message: bytes, signature: bytes) -> bool:
        h_len = 32
        s_len = 32
        em_bits = self.n.bit_length() - 1
        em_len = math.ceil(em_bits / 8)

        if len(signature) != em_len:
            return False

        s = bytes_to_big_int(signature)
        m = pow(s, self.e, self.n)
        em = big_int_to_fixed_bytes(m, em_len)

        if em[-1] != 0xbc:
            return False

        masked_db = em[:em_len - h_len - 1]
        h = em[em_len - h_len - 1 : -1]

        if (masked_db[0] >> (8 - (8 * em_len - em_bits))) != 0:
            return False

        db_mask = self._mgf1(h, len(masked_db))
        db = xor_bytes(masked_db, db_mask)

        mask = 0xFF >> (8 * em_len - em_bits)
        db = bytes([db[0] & mask]) + db[1:]

        ps_len = em_len - h_len - s_len - 2
        if db[:ps_len] != b'\x00' * ps_len or db[ps_len] != 0x01:
            return False

        salt = db[len(db) - s_len:]
        m_hash = SHA256.digest(message)

        m_prime = b'\x00' * 8 + m_hash + salt
        h_prime = SHA256.digest(m_prime)

        return secrets.compare_digest(h, h_prime)

# ------------------------------------------------------------------------------
# Shamir's Secret Sharing over a prime field
# ------------------------------------------------------------------------------
class ShamirSecretSharing:
    class Point:
        def __init__(self, x, y):
            self.x = x
            self.y = y

    @staticmethod
    def _random_mod(prime: int) -> int:
        return secrets.randbelow(prime)

    @staticmethod
    def _eval_poly(coeffs: list[int], x: int, prime: int) -> int:
        y = 0
        for c in reversed(coeffs):
            y = (y * x + c) % prime
        return y

    @staticmethod
    def split_secret(secret: int, shares: int, threshold: int, prime: int) -> list:
        if threshold > shares:
            raise ValueError("Threshold cannot be greater than shares")
        coeffs = [secret] + [ShamirSecretSharing._random_mod(prime) for _ in range(threshold - 1)]
        points = []
        for i in range(1, shares + 1):
            points.append(ShamirSecretSharing.Point(i, ShamirSecretSharing._eval_poly(coeffs, i, prime)))
        return points

    @staticmethod
    def reconstruct(points: list, threshold: int, prime: int) -> int:
        if len(points) < threshold:
            raise ValueError("Not enough points to reconstruct secret")

        pts = points[:threshold]
        secret = 0
        for i in range(len(pts)):
            xi, yi = pts[i].x, pts[i].y
            num, den = 1, 1
            for j in range(len(pts)):
                if i == j: continue
                xj = pts[j].x
                num = (num * -xj) % prime
                den = (den * (xi - xj)) % prime

            lagrange_poly = (num * pow(den, -1, prime)) % prime
            secret = (secret + yi * lagrange_poly) % prime

        return secret

# ------------------------------------------------------------------------------
# Merkle Tree (using SHA-256)
# ------------------------------------------------------------------------------
class MerkleTree:
    class ProofNode:
        def __init__(self, sibling_hash: bytes, is_right: bool):
            self.sibling = sibling_hash
            self.is_right_sibling = is_right

    def __init__(self, levels):
        self.levels = levels

    @staticmethod
    def _merkle_parent(h1: bytes, h2: bytes) -> bytes:
        return SHA256.digest(h1 + h2)

    @classmethod
    def build(cls, leaves: list[bytes]):
        if not leaves: return cls([[SHA256.digest(b'')]])

        levels = [leaves]
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if i + 1 < len(current_level) else left
                next_level.append(cls._merkle_parent(left, right))
            levels.append(next_level)
            current_level = next_level
        return cls(levels)

    def get_root(self) -> bytes:
        return self.levels[-1][0]

    def get_proof(self, index: int) -> list:
        proof = []
        idx = index
        for level in self.levels[:-1]:
            pair_index = idx ^ 1
            sibling_hash = level[pair_index] if pair_index < len(level) else level[idx]
            is_right = pair_index > idx
            proof.append(self.ProofNode(sibling_hash, is_right))
            idx //= 2
        return proof

    @staticmethod
    def verify(leaf: bytes, proof: list, root: bytes) -> bool:
        h = leaf
        for pn in proof:
            if pn.is_right_sibling: h = MerkleTree._merkle_parent(h, pn.sibling)
            else: h = MerkleTree._merkle_parent(pn.sibling, h)
        return h == root

# ------------------------------------------------------------------------------
# Blake3Lite: Toy "BLAKE3-like" hash
# ------------------------------------------------------------------------------
class Blake3Lite:
    @staticmethod
    def hash(input_bytes: bytes) -> bytes:
        if not input_bytes: return SHA256.digest(b'')
        chunks = [SHA256.digest(input_bytes[i:i+1024]) for i in range(0, len(input_bytes), 1024)]
        while len(chunks) > 1:
            next_level = []
            for i in range(0, len(chunks), 2):
                left, right = chunks[i], chunks[i+1] if i + 1 < len(chunks) else chunks[i]
                next_level.append(SHA256.digest(left + right))
            chunks = next_level
        return chunks[0]

# ------------------------------------------------------------------------------
# Argon2Toy: Simplified Argon2-like password hashing
# ------------------------------------------------------------------------------
class Argon2Toy:
    # FIX 2: Drastically reduce cost parameters.
    # The original values are far too slow for a pure Python implementation.
    # These new values allow the simulation to complete in a reasonable time.
    TIME_COST, MEM_COST, PARALLELISM, OUTPUT_LEN = 1, 1024, 1, 32

    @staticmethod
    def hash(password: str) -> str:
        salt = random_bytes(16)
        hashed = Argon2Toy._hash_internal(password.encode(), salt)
        return f"$argon2toy$v=19$t={Argon2Toy.TIME_COST}$m={Argon2Toy.MEM_COST}$p={Argon2Toy.PARALLELISM}${Hex.to_hex(salt)}${Hex.to_hex(hashed)}"

    @staticmethod
    def _hash_internal(password: bytes, salt: bytes) -> bytes:
        num_blocks = max(1, Argon2Toy.MEM_COST // 64)
        memory = bytearray(num_blocks * 64)
        seed = SHA256.digest(password + salt)

        state = bytearray(seed)
        for i in range(0, len(memory), 32):
            state = bytearray(SHA256.digest(state + i.to_bytes(4, 'big')))
            memory[i:i+32] = state

        for _ in range(Argon2Toy.TIME_COST):
            for i in range(num_blocks):
                block_offset = i * 64
                ref_idx_int = bytes_to_big_int(memory[block_offset:block_offset+4])
                ref_offset = ((ref_idx_int & 0x7FFFFFFF) % num_blocks) * 64
                for j in range(64): memory[block_offset + j] ^= memory[ref_offset + j]
                block_hash = SHA256.digest(memory[block_offset:block_offset+64])
                memory[block_offset:block_offset+32] = block_hash

        acc = bytearray(seed)
        for i in range(0, len(memory), 64):
            acc = bytearray(SHA256.digest(acc + memory[i:i+64]))
        return bytes(acc[:Argon2Toy.OUTPUT_LEN])

# ------------------------------------------------------------------------------
# MAIN SIMULATION LOGIC
# ------------------------------------------------------------------------------
def simulate_users(num_users, hmac_shares, hmac_threshold, prime, users_coll, roots_coll, audit_coll):
    users_coll.drop(); roots_coll.drop(); audit_coll.drop()
    Logger.info("Cleared existing collections in database.")

    aes_key = random_bytes(AES_KEY_SIZE_BYTES)
    master_hmac_key = random_bytes(HMAC_KEY_SIZE_BYTES)
    master_key_int = bytes_to_big_int(master_hmac_key)
    shares = ShamirSecretSharing.split_secret(master_key_int, hmac_shares, hmac_threshold, prime)

    rsa_signer = RSA.generate(RSA_KEY_SIZE_BITS)

    docs = []
    for i in range(num_users):
        name, age, email = f"User{i}", 20 + (i % 10), f"user{i}@example.com"
        password, fingerprint = f"P@ssw0rd!{i}{pick_random_punctuation()}", random_bytes(16)

        enc = AESGCM.encrypt(aes_key, fingerprint, b'associated_data')
        composite = f"{name}|{age}|{email}".encode()
        meta_hash = SHA256.digest(composite)

        doc = {
            "i": i,
            "name_h": Hex.to_hex(Blake3Lite.hash(name.encode())),
            "age_h": Hex.to_hex(Blake3Lite.hash(str(age).encode())),
            "email_h": Hex.to_hex(Blake3Lite.hash(email.encode())),
            "pass_h": Argon2Toy.hash(password),
            "fp_nonce": Hex.to_hex(enc["nonce"]),
            "fp_ct": Hex.to_hex(enc["ciphertext"]),
            "meta_hash": Hex.to_hex(meta_hash),
            "meta_hmac": Hex.to_hex(HMAC.hmac_sha256(master_hmac_key, meta_hash)),
            "sig": Hex.to_hex(rsa_signer.sign_pss(meta_hash)),
            "hmac_key_id": 1,
            "shares": [{"x": p.x, "y": hex(p.y)} for p in shares],
            "created_at": datetime.now(timezone.utc)
        }
        docs.append(doc)

    if docs: users_coll.insert_many(docs)
    Logger.info(f"Inserted {num_users} simulated users into MongoDB.")

    leaves = [Hex.from_hex(d['meta_hash']) for d in docs]
    tree = MerkleTree.build(leaves)
    root = tree.get_root()
    roots_coll.insert_one({"merkle_root": Hex.to_hex(root), "timestamp": datetime.now(timezone.utc)})
    Logger.info(f"Stored Merkle root: {Hex.to_hex(root)}")

    intact_count = 0
    for doc in users_coll.find({}):
        leaf, idx = Hex.from_hex(doc['meta_hash']), doc['i']
        proof = tree.get_proof(idx)
        merkle_ok = MerkleTree.verify(leaf, proof, root)

        stored_shares = [ShamirSecretSharing.Point(s['x'], int(s['y'], 16)) for s in doc['shares']]
        rec_int = ShamirSecretSharing.reconstruct(stored_shares, hmac_threshold, prime)
        rec_key = big_int_to_fixed_bytes(rec_int, HMAC_KEY_SIZE_BYTES)
        hmac_ok = HMAC.hmac_sha256(rec_key, leaf) == Hex.from_hex(doc['meta_hmac'])

        sig_ok = rsa_signer.verify_pss(leaf, Hex.from_hex(doc['sig']))
        intact = merkle_ok and hmac_ok and sig_ok
        if intact: intact_count += 1

        audit_coll.insert_one({"i": idx, "merkle_ok": merkle_ok, "hmac_ok": hmac_ok, "sig_ok": sig_ok, "checked_at": datetime.now(timezone.utc)})
    Logger.info(f"Integrity check: {intact_count}/{num_users} records intact.")

    tamper_count = max(1, num_users // 10)
    for tid in pick_random_distinct_ints(num_users, tamper_count):
        users_coll.update_one({'i': tid}, {'$set': {'meta_hash': Hex.to_hex(random_bytes(32))}})
    Logger.warn(f"Tampered with {tamper_count} records in MongoDB.")

    intact_after = 0
    for doc in users_coll.find({}):
        if MerkleTree.verify(Hex.from_hex(doc['meta_hash']), tree.get_proof(doc['i']), root):
            intact_after += 1
    Logger.info(f"Post-tamper Merkle check: {intact_after}/{num_users} intact.")
    Logger.info("Simulation complete.")

# ------------------------------------------------------------------------------
# MAIN ENTRY POINT
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Advanced Cryptographic Simulation (From Scratch Python version)')
    parser.add_argument("--num-users", type=int, default=DEFAULT_NUM_USERS)
    parser.add_argument("--shares", type=int, default=DEFAULT_SHARES)
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    args = parser.parse_args()

    Logger.info("Running Advanced Cryptographic Simulation (From Scratch Python with MongoDB)")
    Logger.info(f"Parameters => numUsers={args.num_users}, shares={args.shares}, threshold={args.threshold}")

    client = None
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        Logger.info(f"Connected to MongoDB database: {DB_NAME}")
        simulate_users(args.num_users, args.shares, args.threshold, PRIME, db["users"], db["roots"], db["audit"])
    except Exception as e:
        Logger.error(f"An error occurred: {e}") 
        import traceback
        traceback.print_exc()
    finally:
        if client: client.close()