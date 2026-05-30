# -*- coding: utf-8 -*-
"""
Chiffrement en Python pur (aucune dependance externe).
AES-256 (chemin de chiffrement uniquement) + mode CTR + HMAC-SHA256 + PBKDF2.

Construction : encrypt-then-MAC (AES-256-CTR pour la confidentialite,
HMAC-SHA256 pour l'authenticite). Cle derivee du mot de passe par PBKDF2.

Ce module est concu pour etre embarque tel quel dans coffre.py.
"""
import hashlib
import hmac
import secrets

# --- Table S-box AES ---
_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a, b):
    """Multiplication dans GF(2^8)."""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        b >>= 1
        a = _xtime(a)
    return res


def _key_expansion(key):
    """key = 32 octets (AES-256). Retourne 15 round keys de 16 octets."""
    assert len(key) == 32
    Nk, Nr = 8, 14
    words = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        temp = list(words[i - 1])
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]                 # RotWord
            temp = [_SBOX[b] for b in temp]            # SubWord
            temp[0] ^= _RCON[i // Nk - 1]
        elif i % Nk == 4:
            temp = [_SBOX[b] for b in temp]            # SubWord (AES-256)
        words.append([words[i - Nk][j] ^ temp[j] for j in range(4)])
    # Regroupe en round keys de 16 octets
    round_keys = []
    for r in range(Nr + 1):
        rk = []
        for c in range(4):
            rk += words[r * 4 + c]
        round_keys.append(rk)
    return round_keys


def _add_round_key(state, rk):
    for i in range(16):
        state[i] ^= rk[i]


def _sub_bytes(state):
    for i in range(16):
        state[i] = _SBOX[state[i]]


def _shift_rows(state):
    # state en colonnes majeures : index = col*4 + row
    new = state[:]
    for row in range(1, 4):
        for col in range(4):
            new[col * 4 + row] = state[((col + row) % 4) * 4 + row]
    state[:] = new


def _mix_columns(state):
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i]     = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
        state[i + 1] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
        state[i + 2] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
        state[i + 3] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)


def _encrypt_block(round_keys, block):
    state = list(block)
    _add_round_key(state, round_keys[0])
    for r in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[14])
    return bytes(state)


def _ctr_xor(round_keys, nonce, data):
    """Mode CTR : compteur 128 bits big-endian commencant a `nonce`."""
    out = bytearray(len(data))
    counter = int.from_bytes(nonce, "big")
    for off in range(0, len(data), 16):
        ks = _encrypt_block(round_keys, counter.to_bytes(16, "big"))
        chunk = data[off:off + 16]
        for j in range(len(chunk)):
            out[off + j] = chunk[j] ^ ks[j]
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)


ITERATIONS = 250000


def _derive_keys(password, salt):
    full = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                               ITERATIONS, dklen=64)
    return full[:32], full[32:]   # (cle AES, cle HMAC)


def encrypt(password, plaintext_bytes):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    aes_key, mac_key = _derive_keys(password, salt)
    rk = _key_expansion(aes_key)
    ct = _ctr_xor(rk, nonce, plaintext_bytes)
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    import base64
    return {
        "v": 1,
        "algo": "AES-256-CTR+HMAC-SHA256",
        "kdf": "PBKDF2-SHA256",
        "iterations": ITERATIONS,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
        "mac": base64.b64encode(tag).decode(),
    }


def decrypt(password, blob):
    import base64
    salt = base64.b64decode(blob["salt"])
    nonce = base64.b64decode(blob["nonce"])
    ct = base64.b64decode(blob["ct"])
    mac = base64.b64decode(blob["mac"])
    aes_key, mac_key = _derive_keys(password, salt)
    expected = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise ValueError("Mot de passe incorrect ou donnees alterees.")
    rk = _key_expansion(aes_key)
    return _ctr_xor(rk, nonce, ct)
