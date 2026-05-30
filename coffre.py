#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COFFRE - Martin   (application locale, hors-ligne)
==================================================
Ton coffre de mots de passe + ton planning, dans une vraie fenetre,
uniquement sur CET ordinateur. Rien n'est envoye sur internet.

POUR LANCER (Mac) :
  1) Installe Python depuis  https://www.python.org/downloads/  (une seule fois)
  2) Double-clique sur "coffre.command"  (ou : python3 coffre.py dans le Terminal)

Chiffrement : AES-256-CTR + HMAC-SHA256, cle derivee par PBKDF2 (250 000 tours).
Le mot de passe maitre n'est jamais stocke ; il ne sert qu'a dechiffrer en memoire.
"""
import base64
import json
import hashlib
import hmac

# ============================================================
#  Dechiffrement en Python pur (aucune dependance externe)
# ============================================================
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
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        b >>= 1
        a = _xtime(a)
    return res


def _key_expansion(key):
    Nk, Nr = 8, 14
    words = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        temp = list(words[i - 1])
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // Nk - 1]
        elif i % Nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - Nk][j] ^ temp[j] for j in range(4)])
    return [sum((words[r * 4 + c] for c in range(4)), []) for r in range(Nr + 1)]


def _sub_bytes(s):
    for i in range(16):
        s[i] = _SBOX[s[i]]


def _shift_rows(s):
    n = s[:]
    for row in range(1, 4):
        for col in range(4):
            n[col * 4 + row] = s[((col + row) % 4) * 4 + row]
    s[:] = n


def _mix_columns(s):
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
        s[i] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
        s[i + 1] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
        s[i + 2] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
        s[i + 3] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)


def _encrypt_block(rk, block):
    s = list(block)
    for i in range(16):
        s[i] ^= rk[0][i]
    for r in range(1, 14):
        _sub_bytes(s)
        _shift_rows(s)
        _mix_columns(s)
        for i in range(16):
            s[i] ^= rk[r][i]
    _sub_bytes(s)
    _shift_rows(s)
    for i in range(16):
        s[i] ^= rk[14][i]
    return bytes(s)


def _ctr_xor(rk, nonce, data):
    out = bytearray(len(data))
    counter = int.from_bytes(nonce, "big")
    for off in range(0, len(data), 16):
        ks = _encrypt_block(rk, counter.to_bytes(16, "big"))
        chunk = data[off:off + 16]
        for j in range(len(chunk)):
            out[off + j] = chunk[j] ^ ks[j]
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)


def _decrypt(password, blob):
    salt = base64.b64decode(blob["salt"])
    nonce = base64.b64decode(blob["nonce"])
    ct = base64.b64decode(blob["ct"])
    mac = base64.b64decode(blob["mac"])
    full = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                               blob.get("iterations", 250000), dklen=64)
    aes_key, mac_key = full[:32], full[32:]
    expected = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise ValueError("Mot de passe incorrect.")
    return _ctr_xor(_key_expansion(aes_key), nonce, ct)


# ============================================================
#  Donnees embarquees (chiffrees)
# ============================================================
_DATA_B64 = "eyJ2IjogMSwgImFsZ28iOiAiQUVTLTI1Ni1DVFIrSE1BQy1TSEEyNTYiLCAia2RmIjogIlBCS0RGMi1TSEEyNTYiLCAiaXRlcmF0aW9ucyI6IDI1MDAwMCwgInNhbHQiOiAiUjBJZUpKVkpQU043Q3FBTndNNU1IQT09IiwgIm5vbmNlIjogInVhTDF1S1BGUm5MRk5VZnRiSXhJTUE9PSIsICJjdCI6ICJ1N04rWlo5UmxhL3E3NFM1YU4zODRiUlhPQVR3NW1CWGJPT3lpSU1tZTdUUHhPKzR3dzdsOGFoaWo2dUhnVEFIUnB0SmVteGY2Rk5BTlZrdlRTSDRlRFUzSm1INnJEZTZhK2JSVW5RS28rWFJraVkyZFRIYVhSQ0creWd4c2doS2Y0RDRvZGh2b1F0aDMvRHdieTR3M3hreUROTUZmeWN1TCtJWC9UOHhZTVRtTVMyWHNzUmpjVWVjNmJRSndUNEFaTnFITC8xdEJrbE83WDNhbEFGM1JkUjZsS2hGbGlaNkt4WjhHejFYSDZXU3BVaTVTeVZaaHZ2VlVuT1pHeWVpYk84QjdNV2hzdmMwalRFd2xwd0tGNnhsa0JqU2ZHM056NytuR3E2SVhtUTB2Z2c0T1FqTUozU2J0dWJ4aE9KWTUwNkxMbW1hUy9OVzJHSXdNUjFqSFkyS09Eb2p6cGZiWVJyRVdBWXgxYmxuK1F6WVdFOFg3WklXT0pLQkFsS2dadmdiMlg4NzJ5UFZBOGkzWWdNMWdESUZYRG9FS0w2MmFtbDdjdUtKai9SSkNZUk95a0NPc3lmZmg5SGJzanN3TFUrVzdNbE5ET2JYV0FPWno4VzAwemR4ZWtCQjc0eHd6QUorTWVZNFhLMnl5VEhNT1FjK1VLUURTWjkvK2VtVFBQYSs3YWZWTW5nckEvZTBzbG1palF2VkszS09HaWhEMWxEcjdOck81UWJGMG1aeEZZa1ZIYWZXMk9GbWRJdjI1MExqVE1VUTBUWnl5QzdYZHh2UXFxM1dHcEI0ZmcvZkpvWmpKN3pJRFNFVDJVT0RLQ1pmNCtpZ1R4citzMmhGb1lWMHloYzdvVnJxMUNacUFsKzZpZG9weGowM3pha1VGcDlQVXk2cDVUcmhDa1M0SFBQeEl5c1VUVnFBb0xsV2dlK0p4MEpwRStZUUtuV2YzNjRzSzBWKzMzaUloK1B5dFNWaGN4UkdBUTdlMDRFNlNiV2FKQXVlREp1YTNZTHZUV1BSU2o4RVRnZytkblg1MnUrS1lvWllYZ2lsUC9SUlZvTHY0VDVmTW5RdnVvOUhNYS9vWjV0SVUvcnNoQjJOMkhoYnZrVjRRelVYZERIK25FaVlOdW1uQm4xcEpOMHc4c2t1MHpYMFFycFhmSXN3Z2k2eENsMksrYldFNDRSbkl0REZHZnQrQkw2a3JZTnR6MVhzdXhYLzRyRVBtUHFHcUEvc0dzVTVDMHc3NFFqY1MvejhabWIrWlpRbVFmVDZYWm43WkVRblJ1N1d2bjZkUDZtMUdlaUdILzViOVgza09Wb09ReXNWMDFRVlYvRjFYYlczWWtwYXBYd2x0Sko2M29LZ0NyZmlOYXFidUlHR0ZCQ2hERmM0NldlUmFaTTREUTlBWkZyUHQzYjNuWWx4cU8rUTRHcDg2ZXFYNHh6NTJSQSt3dm1mSXRrWnI5cCtXSTFwZnJqakU2R2xXRlk3d3YzaWR5MXN1SE5saU05ZTlMenY4TnMvYkhicytyOEUwby9UMjB0cFFkSm50TkhzZDIrMzA0ZzdFZGhLZE8rOVZRMFpnYXBIb25PcmNRVXc0UnRHbE1sRmdLSWt4eFpmckE3c1NseWFIWEdFMVp1bUFHbWU4c3UrVW4xbVJkeUVpVWhlUXZ6Z2NTYWs0NnpTWlllSjgxNmJ6M2pYUHR0QWhPekVtNjlRYlplVFhOaHQ4Zk1FQnVWaEhvZk1RZUJUVEs5MFpVaFhVRmFhNnhnV1U3L21SeCt6dlU2UURLTFpCM01jVnRkNlhqU3R5VXlEdGVCVEUyRUtVa3FKNmxXM2c3bS9UenAvZnZSRENwTlZ0cUxTS1IzR2dBWmQ1OHJvaTMwYmR0U2ZweHArTGxIV2VuZDlVSUpGTE0xYXFwZjNLWUoxaURrOWJhZm56MEdRZWRhYWVHa1JkbzMrY3BFZkdYWXZ4WEVwUWtycy8zZjhpcmtyOU1veS9EQjI2UVB6ajhsb0IxOXo3ZGU5aFUwYzd4dUZzZUptOVVDZGZHSFQzV2pkNHkvcEhUTjhCb0grc3AyakFjSGFrUlBlRW5RamtFSGVQS09EODQzcFlzUitxKytUSlBUc3BvMUM2QWpqbFVFdEwrdkwvVENYTkVGQml0T0RFbjYwM283bVE3OUpCUzgxbE5BT3FDZEF5cjhXTnQ3ZkpGQTNIdktJRkNKSHBMV3NxZFNBVFlqc2poTlpxTjdVYXJjYitGeStyTE5sYVB5MEswSHRJcThOZXZjRlhzOEtQMHV5SVJNWUpyQlRRVzgxRXd4QWtyUUhqTHFJTUF5dWdvK2czRUY4Y3NyTW1pWmFKbG1YazFXamtIRTJhcU12Um1zTVFVaW5HOGRtRngxUFBYTlRaTy9EVEhIczJtUXkxNEdKL2F1T1NIaXVCeUk4eDhLRHVmVmR3NUs0MWxmK3g2Y0sveUZWM1NTOGRCK2RJVVRQeDdXeW1zUzIvc3R6b2ZaQmxwTnZOMFkrckVnNlRHSjN4NnprbWtjSGxKditmUExCUVkrZ25LSkhNYlVTUlIyZmVaMVlLZzdsM0VkTVpLRlZmMEVzL0NWM09rSUxTcVNxaS9WN09PelVIVFE0OHhUU1R6dWNZMTFQaUo5bXdaS0tHOGYxZTNSS202WDdpdHByVThVbHZOWW1DWmp1Wk1veFFxR09zb1I5UzFiU0JUNGZwREFLM1BMRnJPalNLVkNzMHRZeUZXSU1FVXMzWVhZNm5XbUQ3cnJ6bjdGNHJoM2ZYQzU2Vm5SZmNZYURiaXQramxEazdKdytwdnJJSVk5RU9ySFZaMjF1bWNMajQxTkV1Ly9Sd2swbjN0WkUyKzdHUE9tZkEwcVJCdW5QbmpmR0o0RjN2TGdMTG1mdDI2cWpRMVF0UEdUSUZKc21RU3JtR1dxcnRNYlhzdkdTOEpVYXFsTUxoUXEwaU0wSkl1T0xWbGpRVndOQWlEYW5WTzZqYTlhWC9xWWpxREJQUHVGMHl4d0h0cVJDTi8rR29HZ1FyMXJxZHA5VkNpM2kzRUlWT2l1K2gvUlF6UFY3MlRJUzVKQ1FENHhVRzc0aklpZlZYcmRqUXl0ekFibjluOUh6WEZpdTVZQ3lGRzJHNGY2c0NkTWc5ZDFWSnB1Wmpxb1hCdDdEY1VubUdOcFNaVEd0US9ORHBxT2NoQm0xeUpuWEdFMWF3UU1LVCt6aGNYYWsrUk5PRXF3K3E4aXliS0d1Sk9vSm1sQ2c4UWY3MlllT3M5bTR4VUQ2R2diWnpwanRQakdXS1ZuN29WRFp5bTVlbVMybkgxQ2NySWtUVHNFalZrc2sweGlwdlEwME1EZkg4MVBlMTlBRHBISVZMQ1ZwQ253UVJZQVFOS0ExMi9TMjFIZTFPT2VVWWl0dWJiWTVtMm5vU09FdTJ0MGZkcEVTK0Y1Nk5vMm1kOGVQdUlxajFlL21LUmd2YUU2ZmtzSDBtbjNqVnFiWlM3VUdGY1BpNkl0WUNudWJtZy9iNjNQNlpXaFJsM0NZUjNUQU10NWhRSVdMWXk0SU55dm9BdCtkS0ZxRXVKWjkvTXVtRFVmdzRzMnJLeGFXbW9hMTNtOE5HNXl5QTZQMnZSS2dFcXhHS05PUW5xQmV0S0tGdHlSWCtZdWpia3o1U3UrRWtwRDYyRWZBUjdRcHZjMk9rNUtWYXB1UTA2dUEyVG5wWmpaUk1kMkZSQ2dHdHBnallkNjJkRGs0L3pxdzNPYXp2NUJpUGZZdERpT1RpWWF1MW9kd01CblZTVmlDNVNRQUwwT1VhbTVBTHA3TkJZZXBVUzNlWWs2OFRDa0pqTHEyUThtK2hiTEVmckkyVUpQUGEzVjBXV1RaVjVkRFpETXpvYlRHdXJhalhIWWxkdENBaFg4MHRDbGxEMkxHd0NwVEhRRzYrcndDbjBWVUZ0MlRiZjN4czFhdU1SZ3dBZjlQZ0VSZG5OWVZFa3VzQzd2amRueVdhNEpTTENYRjhtUlZIVm00dVhjdnZXbFoxcTM3RDdoZ0REdDZ1andJUk5ob0g4b2JILzNML0pNN0N2TjBVbUVJTkkySThEczBCR1J5YTdjWldvTnlKNkhQM2ZLNmpXZ0U0cE04WVRWSVJYdXY5QUE3aGhpekJiK2ZmclhKck81RjJrY2QvV2I1K080MGlFSHRRTDNGKy9qQVRUNG51MFlwSUtjemRVQW1Ed2d3SWxaeFZaK3RJM2U0NzgwYkRxdERvbjdTRDlkeVQ4SFhSZVRwaWhRR1RrWktoTmFqRTRvMmptUXRBVFNnVlc1RzFxVndnUjhSRG9Xclg0RG42SlBYMlRQTWlhaVBUamRhYnl4ZkxuYjU5dFc3Y1VrdU1ESHA4SG1RMmJ2MlFacXFHV3BGM0Rrb0pIcGU4VEdML1hpM0FEV2tXbVowK1NPaU00Q3Q0TGViQWdXa2JvNTlLb1lDZXk3UVRXWjJBN0Z1Uit6U0ZqWmdDUmpNd2hmUGlyenBiTnRmRjJWcjhjUVd2bDRDcGpDYWxSY3pPNDFycXB4S1VRcDJrZmJnSzhkeE80Ti9KQmtwZHg5dDVCYlIyMHgrQm1Pb0hXQjk1TWhqQ2E0WkxaUGJ6MUgxTHNITXNtNGdzVEJTRzFGYlFDSTdSeTIzdjFUWmpYTTFrTFhUZGg4b2JVS1dHK2xoenVVcWFJTUFWQjhTcndVeXdDblpYK3FPV2FwenJVV1RCa2RHQ0RlQmkrcVhoNDk1SEtFbXk1SXh0UmxlRHh1RjBqaHFETjNRS3BpSDJtRE1hMnNaZVlodmRVU2xWTDNNcWVKTWRPU2liMHVtZ1ViOXFRb2lpZlE5R3JUcGFoL1lqdVJIUE5EbFhoU1dxWTJkYlp3RnZPU29CenNFa1gzdWJVKzdUT1BRT2NRS0p3eTV1Vlh5VGNpU2VvWkFVUmc3dnRmU2k0SkFFWHcxMXNvZ2FRck1FUTVaRURuU3JiZXhCYUlqcXc3VThwMC9xcHZtVC9oOTFYTUtBSXh1d1lVTU1LMzZicUE1YTRNRzVEZnYxOUZxb0RSKzFFYmlIQWErczhMK2hBVGd5Vmw5dzJBUDBoTmhTL0NKVGpWWWlXRlRQSTJSbU1ndFhFamxRTVNUOFBkT0kyVmVETElONE5jWnQ0V3k2bjlRaWhPalRhV1RacERQSmZWaE1MT2NQTjFhN3NDbDh6OVRlbEdaTkl2aG1nQVhRbTNhMjh1NVE2UWpkR2k4WnV5eFY2N01hTmw1VGVLRnY5clFialJnSk5yQy9FQisvRURnUTd6b1JHb2wzVzBDc0tON1dXKy83eTlpRmZBcEZrcDd5SmxTeEVsT2Q5MCtWYnpiNUh4MTdJUGI0V29nOUV1NXNTQVREVG9uR0ZKWUVFYWZkVW9YdDIzMzAzWnB2dkVib24yMEowS0FrTFM2akNMUjJqMGJGaVZvZEswSlhDNVNVRS9xYlYzZnlmbTFmcmdoZkNWUmRReW1qNzFjRHRCU283c2lvSmpWUzY3Z3F4YWRib2QrZjRLckRrMlB0WENTbmVidXFXczJTY2ZNWHIyM0UrVGJxTDZZckY2V283Szc3TG9HTW1ZSXFPYktDVE9va1pHdUE3S3FOdHFkcGJKQVkxQ2NKZmVPcys3Mzl2Q2htYnBKb2kwakI1ZTZMM1QrYWtNRklNcThYYXgyQlFQRXNrUldhKy9oRVhJTXcya1NJOEVvZ0JNNUppbElNWXRoWTNVek50Zys4UFhaZE1kREZaYzg3Mms0Y0VUUmh1UlJXMVBmenZ1dkNwRFFyWUdJdGVyOUFqVUV0MmpHRjVyMDJGYTVBSkE5eHhDTE4yL3AxRTRvaWRnVTBWYW1MazhUVmJnRUI2bjRCYTNJa2NCNW1pR2VsaVNFUGI4dDM5cUdwUzUwMDlFTFkzbzQ4RzJucDNjWE42dUJMSHV4WVljMW5JYXVldmIzVDVHMnFOdzRFYnJqbzZYQVUzQXF5dk1CTGFGaGlDVGR2WHNZYThpN2NaZVI5QUx4RVNOWTZrenRkazF5WlcxN3dsUWhzUmJoTFBMQWE3ejFPc0RBZmJicDlmYTdSZ0JEQlcxMTFtYTJCNjhEUGUza05FeDF4cXVOZFFRR1VySEFvclNqVFV6YXdEbVdHS1cxL0hJYlVoeUcyaWhldTI3OVlYbW5FdkJuTmJNdFFoaFh6NTJ5aHZhUnhRV2o2T1kyR2paQnpwcCtXTFVvTFNISWJOTmZIeXlFRXZOcVNWS3NFRDJyd2NuMFU2elcwYmlvTVpobDFjdStHd3NZbTZLdUxMUWI3dy9BWmc3U2xpWWd6SUZBV2hWY3lCWmlpaVhzZDNPbHBzNEpoc01xS3RQR0pUSS9oNjAyNXJ4ZHk0VHpWUlV2QUYzM0hCaXVwTVhNdllzOC93VmZ4Q05hbUh5SnQrQTNuOSttWkltanhRbW9Vb0ZRZ2pmSkRSa2EzK2VtUXY3RWtadGxSamNUZTFsU2ZMOUROYy9OVFpWNys1QldKSGFIUFFGMGlzU21LMWRpaHRsUk81RUtNMDJwVzNXYmdmUG9GWFlJYzJHYTVlTnVDcVBnVWh1U3oycnZqazZwQzlERzQwdkpnRzM4ai84QWdkQ3dNdm9iWlBJYi9ER2l0WFNSam04RndwbU9SY0h5M0hUcFAzSHU3cUduYUtDeGN5ZDdGUmV0aU1iRHBQMG91ZlZmTGRjL0oxVCtCYUpCdkYvTE1tVWgrcitWRVJmeWswRytHL3V5akptbHh2MVNrQVBRTjV3L3RVWkt0Y3Q1S3d5RTVCa1VUamZJQVUydjhMSFNFeWxSYlRiTHZWZVdzZ3ZtcEhPV3ZYL1ZqY2ZBZVdBMFVNYnUzMjRFR0M2NU5BMGVSdUxOM2d5bkRZQjRtMlF2ckFIWEkrSkNQbW4rbXhMOGNHVitwZlNaZnJvSC96ZmRyNkJWcVREWnVCUUJTTUpabWJVWUcyTTlramZSUEt4QTBaakZRUHVNaTlka1hkME44R0F6cEZ5MTlkTzBqM01pbXJwNEhLNytTbEVUeVh6bTFJTVFlbWpqOHdHWlAwdEN1VTRXaE5jamJTdkI5MDZ1ck9MamorY3lJZVF1YlZsNWVUUldXb2xETVJtc01tbjR2U0o5WmlhNlU2V1MzMit5WjUzWWJDclZCcnRWVjhlL2JRZGNuVmFuVVNmalVmMjRURWpWWno4YllpZlFzVnJIRzhzVS9CaXNWdGx1dGpGRlZyNzFEd0lnN1JTMHRqSEtuQUxXa0JNMzZSeTRrK0p4TDZNV0tCNDFCZUxaT2lHWHA5T015MmV2QXpERzJzYk9RRlh2bzczT1c4cUZGd0EvZVd3bXZZUXZRWjFoZkxFS3lZTWh0MVVDdDg4RVlzRDIxUUxOb1lyUFViSFVleEpOV21wNGgrck1Fd0xmeklkNGliOWlzMHpoRHVrSjlKY0d1UUZCNXZPL2MvVTZSZ1VFTERnRjlSTk5aeVgyaXdmL0Y3NC9GQk91OFhUMlZuSmhPRDRsa2Q5dkVPdUxZOGlnMVByRDY3TmFGN2hHQWN0RlFobjBRbWJZV0hic1JIR200bmNpai8rc3J5Vy9JMGFabkd5YzlEOXVHZlRIZ3JwVldZZE95ajhtZXBUWVFZbE5CVnZaSlhjeDZobWhKOTgvQjBMQW1pNytZZDJiMG9TN3lnVlkzc2grdVljL2hQWDJBeUZCTlM0d1ZzWUpPMVRadVczZW5ydFM3OTlITmlvQmRWMER1VUhXZ1JDWHU2WVQvSGRSSzdQc0lWTStJMlI3UDRsbXdkd1cxanBVUDZDWFJVZW5VL3liR2I5U0crL3FLRnZ1UWRWRFBDeTFPNzFtcHQxREtWZ09sWGhmUDllSWx5dUR2UkRhaHB4cmRnUHNRaklwbHdoenlEMWpkR2MvOXNVMVN6MUhoeUxVT0RaRit1T2F5Z3dTUjNVTWwwVEhoa00xdytHcElmSmxvUDB3Zko2ZG96alRpUFU0U0pNOCtpaVJzNCtHSEsvTnUyUG1JSWpSTkFjT3UzWDVkSWFNWW1BVWg4UlBhOTA4WjA1VysvazBLRkZXczFCRUdmVk1tODE3ak84c25zVGdHZ0xjeTB2MGZkU1BBT25EYm0xeGtsVVhIZW05UGlyZVNJSDRyUXRwdnhMODJ5ejRQdTFFeTVYbUtyaWN2MWlCa1ZzV1JTcCtkUDNZaHlSS1g0NjlpNTBmbS9pcEV4c1RwTjhMQVZkV1NYUGhNMXNSczltcVp6d1VjOVhrZlp2ME0rZHNQeDU5aTBKTSs4ejdkYWtoUm9IUmRRZVo1SGtSbUpwc3ZtbTNhcnRQM2VDNFhYNk0vVVFkVnVaQ2o5eDBqMWNSZGlkdWthRjNydk5wQ3dwK3JBME5nb1dOQk41ZWozc2x0emRhb2tlOTh0S05WcW9zaTRadm1qbnhITzBhd0F2bmJ2UGxmcVdkZGp3WjBmSHdmWmxnVzNJWlJ5WjZFWVp0eVk1VnRNRzUxZDljRlhwTURIam1keGhERVo5NVp2Y2ZPemt2T0tsd1hUdEc3NVhZSDViY0ovRUw2YUtjTlJYR0tiL0JUVEpMUnNuU3lBKzNsd0kvS1BIbDd0VStOdW9WaURKV1VRRFRmM0JLZFV1NEgvb2U3c3hHT1dCYjAvNjZVRWxyMzhBZEFQMHZuakFITGhVT0ZSd3Y3WHlBNStaZmo2Sng4RzFVSy9FWWEzcXFsWGM0K2tjNDMzcGVQcmpCT3RlTzMyaFlEVkovcW1PQkREYlhaa2s3c0o3NkwwaHNVWFpDc3ZncjNEdnZncG9rb1hqRnJMRmtGZ1ZyakJaN2lBd3dEU1d3VXNIcFlYT1ZXV0RvV3BNd3RNRnN0ZVRxTkJJTGZHblhtclZkZW5IQm9VMEZwSXNkUXA3ZEF6OUtKYzBFRlNVV2NhdzN5emRaOFgzYUZnWlNvbnduM1FqTEJKRXllWlFrK1FLVzR4UkhEekpRRkpRbjhoT0FuZWR0MEEzT1NrUE9KYVR3RWM4ank3Z2JMTmdRRXRGZjZyTC9tenIxU3gyZ2R0cEdTMW5aV0ZTQytUTjJOTTQ2S2lnOHRjcXlDamR1bXN2ZFBWcUJzTUhjTStWSm1OaDdGZDV1aUlyV1lXcDhVNmx5SUQ5aWMyU2duck5xbWFhalJlOUlrZlZZd2pVUkwrZlk0d0MwQVZ3UTFsaWhvdTg5V01zRDQ1STJHYjlSK3FRemR2Si9LK2oxL2MvQ0U2QW92ekhnNGN5K1NiaVpSWEQ1YWFFUFdjK3ZBMG0ydGk4V3ZhVDZzZ2hPZVlmbnFiSUlqRzVaY0NtaFJ4NFdWYTlTTVJ0bzU4ZGowUkh1ZHNlM3ZtRFdGOFBlTkltL2hqckhONEFid3Urak9FYW5KdzBDTlNqODluS3paVzI3cTFYL1VYeVpIVFpuSzh3RnhVRTlwWm1PbVhvNUtMeENibEo1ZU1Damt1VVp6UW9ZMy84dmp4VExMTjNUN0NKcjNObDhIeGYzTlpOektQWGZJWWQ1Y0ZJejUyQ2drNitlVCtQTXFORU5nWWpNbUF1WDRySUJtcmJsYS8vYk9qYWZzTG0wdTR3cVZyVTJaeGZSNW5PcVE2SHN1MUlDN2lIWUxSckYwNWFJZnZwaGJ3Nkh1ckF4M2t0eXJnQTVHeE9uUlNnejlGUU54cklwU0RWNVEwZXlNUnBBYlRGTkgwc1hyQjY5VU1xd3B4dG12OTBXYXFHWWZwUU4wQ0s0Ymw3MDlLcFlTd0d3dzhmSmk3WGJ3TmF6R01qMVRROGNsZ09jWmFlZnZ3V2YzcnBFQXk3RTZoYzFLNmVJdG5DQkJRYStWUTJ6eGZET1I3VWF6Ly9lc1EyQTBWa0I3Y2lkdkZ0MS93dzV6Lzk3WWRuNzlYMTdtOXQ3R0NoQVExNUxsWllzOHd2NVE4dm93amp4ZTFrc1Q2YmExQUN6blh6c1FNaWxBcjRUdnZaSVQwR2lMbG52QjZnM1VWQk52QWc0eU9qbUhSR3RmZWgxMjZSOHBabEVpNWZoK0dVOTVmMkxVdkNHZ001MllFWHA0Y1RPdkxUZkxWcGw4VXp1aGYvRW4zaU1OMU05UkkrcmxLOXRLSHVnMXdkeW9GSVJVMDdHL1RPT2xJUXFPZmJVZURMbmVhblM3WHh1VDRaVGJtZXFITEMvWVczNzh6cVdJbGJhYUNwbWcxdkJyS0RoVWtldDBXSlFVTjVHNTlVRWk3SGphRFN2T3ZSRU1CL2tva01vQkZKNzA3WUN6S3pzNjdjalJxM3lmWjdqWmJla3hrL0ZKQnRLY3hZbHEyWHQ4VFlTS2dCb2x0S25OQjgrSnhPamtSVy9LRWdRamJwVm1LWUlCNlRNMHJDZVF2dHo0c2NoT1l0d1lZUzF6RFNYZmNiS294d05NSHRCMENZNThJNTRteUZGOFdKT1pCc3poRlJkT0hZekFBWWNWMWdVczZOT0NzL2NEWTBKdFpIMFIvUVBwZFh4WVIwZ2hraC9qdDJ1eWhvamVGejUzeG5kMmgxRjFCRGtJbFdvSksvTnUvOTlZWjFsRUE3aWFGeGJ3UkdRYTFTNXNxeDBtdVoyNnpKKyt5VDVydnIvTHJNdGhDQ1BwL0U2M0FRT0Z5amdDSURMak5GYzlRNGpiV0FSSENLZWdHVFBXRE8vV2dtOGZFUkI2S1h1OEFqYmZqTExldmhINkRPZVNPTzdwUFJOZlhSU1hFTU9kZ084c2EvelZmNjBSUnZMSFFVckJ6UkllVHIzdEVlc0xubnFXSVprZlZvSUZ5ZE9HN2NLSHgyeUdBVHlIcTM0WXFSQVhqOCttN2RBYjVwamF2ZDNwaVo2SXJPUzRzR2hPMHhNbE9NLysvMFhJZUZNS3lyQnAvdmlGdmovS3FPT0Z0ZXhDNDJKNDYxSFRLdUdRQUl1anFWSWJQUDhHZlJFbWVtWDB3N0lSZ21CRmlPVW5udi92WUhBdDhMOWNBNkpaWWlZeGhkUlRlQi9YQ3pnaXFrak9DWFFibVZpZTlXd1ozR3FvVEFHM3diRzl0ZHBMckNOS1dCc2pIMUlQQ3UzTG45a0hyM2tDSjJQQnNxTVNhS0M5SWszS0xYRlNCMXI4VnVZWDUya2VQcHYvQmR6S0FyQkl5VUE1c3JkNWhvUEg3QXBBbWR2azh5cHYyM1pyQzYvWGgvQ0NxZ1JIRHhXOGdPRjNIbEt5QWRyaHlFQUdLa0ROVTROM1ZYRVlGNkY1RlpWY1AzYTNaeXNFUDZzYVNNejBkSkk4TjlwQlFJMlFLRjd3Sm1YL2U1RkVtNzJFRHBVOEMxYUJUZjkrc1VFellXSlkya1MzcDhTbWh2Q0xnc2JqV1JXZUhFVUs4bVN0ZEF1ZUxoeFdFVlNEYmcyQWR6eStOY2QzK1NjeFBNN2k4T3hSSURzRHFRTzhOOVRwV01vdmp4cHJuM0ZubEhpMnBiaUlIR01LSkNEQlJ0LzBGaXo3dENtQjA2L0FxakMwaUgvMmVHZWxwc0E3aWFXaTd3cjNmL3VZZTl0YTZoakdyb0pvek9uQjhKUS9Oc2RWcDBPQ1YrZEdZZjViT0NZYTIzdVlEMHpwZlkxc2RTeWVNTXI5M2s3b0pBbUlnZFhnNDAxY2JWN0Jua2p1OHdUbXMyY09LQzJmaVYxSzd2Qjk2RGNwUmtyb0R1RlJhdnpaZFZKS2Qxd1FpZ0E2V2VzcFBLWTRWQlBFOXQxTzFRUjBBOWZIa3JVMnZwS1V2QWxRV09vSzQzUktlQXdPNHVmTHhNVGRrUTVRK1VCUVpqVUdEcGp0Z2w5akRzclRaYThBdCtTanNSSGRyMllqYUZmaWozWTM4UXZmaGd1Wk9kMmJGYmIxN2dWOEIwKzJKUmFnWjhpNEdkUmJWeFMxSW9qWlZQQWVid1BZeHczdjdZYU55cjZOMmFtNUpBN1ZDSC96dXRLSUREQWtrTVBKMGZLTEo4N3E5dWljYlkwV1J1STQvVTZjaVV3Zk0yT3duMmtlbTJUclhhRlpUTEZwVzkwSFFwbENTc1hlSGdHRXZiTlJWaWVyM1RzT2tkRC9XOEhzenplUjBzS0daZ1JuWkkySzB5aVdoUWZiSCtiRlJwemdIUXpqWC9TTDc3UFFwb3lvelJBVlRXQlNDNmNYS1d3ZUhvR3FKaVZNa01QTmM3MCtqM1NXZmN0a1BvbEZZOG1UMXJMVm1UZzQxWWFQR0liN0VkRTZKV0dTQi9Rak9lS1MzNTdNeVpkLzZFT2p3K1pMUy9HSkdEL1htVjBCRmQvZGhxMjV2T25kMENYOXJkbE85OGtFTEN4RXlTN3VxUHVDbXJ4YzlSYmVoZUZXSUtxVDEvYnVIZlBia2diWHVIRnNSWk1xV2VLOHRpMlU4bElvUlBGNGYyclNNSUVIbENORm5ualIvZUExMDlGNWthbENMdTdVZ00yeHppNmlMRXZDZ1BnVUk1cjlnUDBqNVN6R2VNL2JTTHVtbVpwc0tTcnVsNnFvRUFON2ZWczkwNUUrRi9EeVZEcW1mU3J1dE1icUx4bHRqUVJJL3BGajBEb2xYOFI0czJWcXRJQ1o1MEtBMHU1V3ZSbTc4aUxWYUlCamF2MXNaSG1nMmdPaHFzRis3eFVqakh3STlLN2R3S3BWVm5FRmZ0UENIRHNpZCt5N21yQ3lPOGJTR0p4UWMrNUdVa1duNmxLN3c4eGFFWVZBUkgzOWdHMENmSjNQaXg5M1NPOCtsT0FOc0o5YW8wdTJKN05WMFhReCtIeU5tdFdxVnF3UWRvbUFjQVBtcjZucFdiWGFkcmdhMkQ2b2Z0UGFabERVTWFIdkFCNWR0azZNZEFCbFhva2JMTXhZdzZUS2FGMjNpMUI2UnJTY2pWUEJRbnlIdG9pM0tkWjF6enN1Ny9nVFdHQk96dCtDYXM5aXA2OVVTK3hTNmE2c0xQSXZtRkc3b3hSZ2ZxTHpGdTVrS1dqWU5PaG5JWUNvMTVhNUs5MHFDYmNaUHpiSHNZNUhvQkJEY3YvWURzV1VWWWJOc1M3UnduVGRBcXR6UXR6ZWlQQW90TWJ6a0pXVkw5Q1h3N0ZxdDR4dEVHYi9MSVU3OXdJNGkvSVpmdGlackhlWmRXNE1rLytnL0V6T1BYbnJMM3FRTU0wMHRkUnNSYktHLzlZZzZDY24ybmEwRWU1WVdHVklQdFJwdld3NHNNRFFJdnIrSzM2RzR2VHNna2pxREpYYklVLzhuMFpDRnBWcTFsaFpOSk1FaXdxNlFEcEZXeExKYlorVGdDQjFqWHJEZCt0WDliOXJwYXBIWlFZQUZtSUVCRlNhSlZVQTIvQ01RWmNwUzhCcUdYZHl6M01uOFB0UkViamxndmw2dHdWWXJBV3RPeWZwd1hzNHV2ZlFWR0NMV2RoQmFIdnd5Q1o3RWt0aEdPU1Fsb0E0TFprUERReGZKTWp2UGJhNldHK1RlQXNiSTRab2EybzlFRklVRStlRlAzbkdlblJxUTV6OUxXSXlkZHJLWHBwdDV6THVtVm5GSjlKUkIxZ0dua2w1b2VCSXZJL2NQVEIwaUJiLzRUWTVnNTZGWm50SkdacERiUnNEOXpCUDlXMGRXVzRXQzdEMHA1alZ3ekx2N2lBWldjcjUrVGx4eFQ5RnhHcXYraVQ3MXREckRNNWNNUWVzYnp2Yk8zaWJ2ZTNoR1lGS3AxZGtlWHZaQzhOK2k0cEF0MUVBVWQrNmJsZlB0eEwvOFZGVHI5Q3ozVWp0Qks3dWt6MllCZDVvVlRxYXdJMnR6cFN0alJwM3E0aTJaVFdybXE0WXd4MGdhbHhISzh4YmlIREo1Z0RoSnBNMWR2Ui8vY1N2dXdBQ3pVSVdEYUFwUGR6RWlLTEk4QU1XRGNSS1E4QUZvRUlMUWY2dEl3Q2lYeThtK2dvL0ZITnh2NjlkaHhpY3ZJR2VPOXdoUG16TWRySHJhaTYxallaVTNmei8zZmFIUDREdHZYRXQrV2FycVFDRm9SUVdvZStHNU9FNThiV2tabmJFVlVXMG9CVFpUSHRLQ2U4OGRHdVM0Vk1JSEE4aGV4MWl1QVZMcUZrWGNGQXRCV0U3ek5JaUt1SWIwRlliSEVxVjJMTlBZVFRPVU94b0psajF6YmlENmRKWmw1T0tDcW9hWnJWSVBNclRDZlJPUnFaWVF6M1VGNXV1U01qL1JOdElPZmlIWlNaVnRJeVhCV2RiOVVqSU40bnFneFVDaE5xWmZGQkRYT1hLVGFodjJaVWZGTmQxVkt4dXB6bG4wZjlVUWJWeTdrSi9jcFcwOVEvM2ozUE1ZTEd0NXVEVDVOSWV4ODlmdVF5cTlya3VTNURpdkM0b3RWSnRlOTBCSGNXbkxZSXBHOG1IOFZYOG5mc3haaFVxT0RxRW1FSHhCWVpvanFRdTZKNFRVdHNBL1cxZGszNEdnVFdLV3ZUMTlOcUh2QUNHNkl4cXV1aG9QZnhUVWhtUjgwbm84V1JiK09zNkhMOVBMMzBPYTB2ZU5pQnNKb2V0OHJ1VlBaVGxzdVpNd1R1QlRBMXZoQ2NJQk1ZWjh0dnRmU1NXSXRreDJxQmdtazBKU0x0WmQ4RTVxRUc5Umxlb3FOQ0RrMHVUMUdCUFF5cVdVODFsVlB0aTY1ci9DVnJnVmY3dzBlREdSSGJDVGlhdEVLZ1M4OHhTRy82bFVUQ00ySm8xcmgyU0dvKzArNUg1MVJKQVMrRjAzaGhDb2xtaThhSmFaNGZXb2dCeldnZXVwL3ZBSVBmQXQ4ZFhOZzJGTEFLK1Q2TUJyVm9sK0w5WGsrSko4dU5PdmVNVXRBeXNPSjZBK3pNaGdqVjdkeHBsQkdyL0lSWHdTSWUvQ2pVQVJqcVR2Rk1XM0tpZUJ2NVB1RkJxOE9XbzQySEV1b1VnRUVYeXhCUzR2ckoybi9jY1ZZdmVGSkduQkpYU0NoeGNFVEhrb2V6Y0tiVDJwNVZzd3FmVks4L1lvZE8yVExCZ0N6cnRtVnlFRHF1SDJqdkEyUXgrR2VJcTBaay9WNVdoUWxBdmE3b0tseGFqUUJtNkZZK0pJeGlUYktRYXR4YkF1cDRpa0lFQ2RPaHVJckNvOUxlVi9ZZjRMNDNVODlwT1BMT1owdVlqeHoxK3ZoMnE5TDJMeDZzTWpNSTQ0ZEdTc2NzRk5MUDYwaTdIOVB6K3ZkUlEyTXkrczE0QVJnN3puK21XaWhJUzFIY3VXRjdlSTJSMnVuNGNqbDJ3YUF5Ui9OZUhHYldGcUlmVlh4MktXUUdsQlMxV1hlTXlJd0ZiS09XNThvRnVManJURlRDcS9UWllIbTIzaXRnVVl0Q3p3Z0FXT3U0QWhLVFNqREg2bkZ0SGVSS2JOU01EdVljRG1rNjFCejhqcjRnNk9OT21XRXFBdTcrd0hTMFdsY2htM0NiNlVMeVNkRCt6OEdNWkZkZ0M5dGQ4Tm01ejE0YlJpVFJBWWVOY3RFLzd5c0EwMjE1b08ybmxUYzFlRmk5RmU3YUhaQTlSYUFjUzdlOTlxdWJXNWdLQXBjcEJRTmhIc3BHOXRHeVIyTlBGaDNhS1RzVnJKT0tWVUU4cG1ZQUdyRVgrV1RWYTVNUmlWYUw0VlFCRWVKTEt5aGdPblZQQ3dMZEFkNDRPZUFKU0FIdVlXRVlDOUFvNElybmRBN1hDdmhHdHk4WjFSV2s0Vm0zMnl2dmExSGhuQWZuUTRBc3pyd1JmNVUwUHpldjl0N1Z3VWMzb3U3QU15RkFjeldxcTd0V085YlA4OHJaMW55ZGJxQmtEY1JtSUw2aE0vNUx6M2MrN2psUzZSb3RVN2NwRHR4dCs0SSt5YVdJdXl0QUZGd0tEREFnQ281Y0RNS0t3dmpFWVBHRk56enM5TDR2elZ4RkM3V0diYXo3TFJ4RS9Md3RTbHd2dWk1MndrN3hkdjd0NWdDa1lRR1ZaZnpqNkFCYkM4Vk00M3REckdrUFVOL0RleFZ3MDNxaUUvMzN4VHFKZGNFUmNtRFh2YTFlanZleWdLL3pjRm5BT2MyK0NNOStDRnNmMXVwbmZMNWNuMWdVWVpSOGJtT0c2T0crL3FEdHlkY1djL2g4dG40YXRyNnl5UHhCdytEQlgwcTZDeHRCYU5seDVvakNlMnZ2Tm5rZWhYS2s2bjAxLzMyV3E3bG5uTjM1NUVVM3o4Qmp3NWZhc0Y3K25jOFZVOWIxRGFBYjlnTTdoT1BMUHFYYklkYXIwN0M2WklibWIzUThLL3JBbDlMc2Qzb05TcVRRejhJb1M3ZDFkL2hPeXhUdUdJc29SSVFJbSt0RVRIZEVuWmhGRFBXN284NXFISHBhTDYzSm5xbm1qLzZKcGpKN0ZCeDV4dnhGSStvMmZXdDN0NUYwYWFaUDFVQzI2QmhsK1dxTlBSeHo1VU84VXppSzhwcE1jNGxqMVc3bStNNmk2bzNuMEplc0pUK1ZPUE1XWG9wSi9yRmVEcm5UTmZ4aGtWTXFBTmdJdlkyTUo4Y243SFJiRlhkZVd1bjJNVytXUEt0bUlXNEpWRDE1TzBGODcxK3ZGRXg5bHV0YVZOL05YdExQUzJyNUxOaW5CRE9nNUFCY2RqZ3VTVDB3b2tqbS9BTitaNERsY2NJb25ncGlsTk9GanVOSkV5WHgveExEcDR5VHpaVGExSjBxWXV2TzRYZFEzU1FEWFVQQkhUKzRBU29HVlF5N29aeFVlalFrbGU0TXdXdlc3Nk1IaHA5WUJnME1KTTFZMllWNllpcm1SdlFHSUtNaTV2c1RNM04zRkRhTkxoNi9IR2I3TzQxdlhVN21CZUZCczhqUHhrWVMwWXdEMnBwQ2NFQzNUTXd4Z2QrYXlJYllMZDFZQ0xLSWxHdGlva00rWnRnMEpSY1RUOWo4Q1Nlak9sM1d2SWpqNG9ta3MrNU5GY2xtaGpmbURzdld6V2RTbS9TY3FrSVhTaWVBWmlPajdlRFRvUUJ0eGc2UW4wVVRlUFRxR1EwemZMR3lnYW9lSTRFYWFINVBsdHNMZFh6di9XMUVpWmVWM1BQOFZCS3JHRWgvUTFkVXdWU3FWN2F0RlVZQ0xrMnVjcGRMUmFvWTZKSGZFOEFNTGR3WDRSL3lSNDQvajdDWE9hK2pBekNFYUxZY3ZqMGVPc2xLdDBzdEVzNlZKS2QxOUNpcWQ1czhLWGRhaEtxY3BvYld1S3JxeG43N2UyeWRVeEQ1Si9LempSVGwvblVrck55MFh6dXZVZmJGYzEvMitaWDhTaHFZM2pZejVRcFNETkM4RkpyaURYTTV3TnhDSmVRWldWUTZIdjRQTmtrUGg1ajM2SDJqeWZlMnB2eldydWcyUk5aTElMQmFQeEk3cTE1bjJRU0M4MU1vV21Kc0JVUk5xQkg0RVBjbTVCQlUvcTlrQndWT0VqUWQ2ZGhubWZDc3VZUWJFUWlFQW5UNGMzbU5yN3BubU9HLzlxRE1aVXhEOU9kUSs4MHZsSkkvd2x3LzhZWFZseDRtWUQ2MVl5TVVIRmU3KzVGSHZDUEJ1VWRRVkdmRE9uaUVjRFZwbWZWR3NEeWlrTVN5aVU4ejQ4YXUwM0tveFJVRXdreVRUR3VNb01GOVRaakZRdDNIOWdERkNhZnU3TFY5MW1TZG0wU2J6OEpUemVPYnRtZzF4bWg0VGx0MHhxN3Z4dGkxVWo1VWlIWkpHSTNwVkVLSDMxT29yR2xaSUVzSUovK0pLSndJZVZTQTdBQitnQitERXNYRFM2N1RzOUFSOVpLMThoL3JnclhoNU1KZkdjU1F1N3k3ZUxmK3hWcVQ5WVpoMnZJUko5RkF0akJlVmgwK29JOS9vRkw0RHdBenFRWkdMdmluNzMwTXdnS3BXQVRldVA4UDNJTDgrMVRiNWpvOWt5SSswZFR4SytCUVRoRE9qREU2WTkvOFZJbWVrWUVWZ1Z0N3J0c2ZVQkZnakpYZDV6MTcxeE1BclV3b01TcVFMZ2lidm05NHFBQTJhQ3lyeTFqZ2R6TXUxd0ZPZ3hyTy8xSnBOT25pUGZpMGE1djhNVnQ1d1ZQU1IvU1JCbWc0U1RHWjlVTFMrK0tCemtQQWhNajQ1a3U1eU1lZHlGWS9ucGJ3c1ZWWkNpcVU0bnlMZXVlUUZMMEM0RS9HZjZNc0FibkVsaThoTTVVakkwZWxIbGljazZpYmEwZkxYRnlxSEVzcEpQQnJ3dXFtTFJyQnRhTXlOOUNUL0hGME5DZ0VYMktNSTZMNkFMams1TXlycU84Snl1TWNwdUoya0ErZ2o5dE8vS1Z5bDR6TUp2RVd1UGNaZm1OelNzLzZ2aU5tU1JwSVBiMEpBaGYxQzJkdVg1NGlPTno2ZEtNdEtncWlOQnVkbkFGQnIza3NJS0NRY1hrcnR2eEM3bEpleWJxak9pbi9HN2grRmVWeEh0TVRoNWpBSVBncmg3V2NyNDhjYm4rRzVYbnpMbGc4OFdtTnVTSnk1ek5mL1RROWNrM3c5T09vTjI2aTVzdmd4bGRKZTdFK09rNU00K0h5N01reko4L1lmMGptSkc4dnpHaWJQcFJtOFNvK1AybUlYTlhtVFl3YzNHZzAxRjJYd0RudlovQ1pOSDh2Q3Njd09DZmZMWmMycTFwbTdmaTlnRkdCTUtOcnpidk9CaW5vVm5ZRStzeVZyRnh1aUMvTUp6cE10NXIzaWZQZm5tZXNxSjd4ZVB4Z3hHWWI3YkpiWXU4K1lNWEtUN0dwTFlIeWRYREszTVVaYklSMDNUS2NrM2VoT3NJSkdId1dOMHJNTDRwOHV6MmE2Qmx4LytYTWRNZHBZKy90TGdKSnJGeiszanozWEdGMWRHODdUeXVzd29TZzRoMHlRSW1obWpNL0VWNUlVQVRQTlU3ZjlWWHBrMktQY0hHS1ZWck50dHZOaXBOaEhPZ25LbS9vVk4ySjlNOXVWalFxQ2RiMGc5VmlHQllnaGYrZ0MxTFFVRVkyL2JXVFhiam1WV3dvbVE3aERNeElzWjh4Z0lSRFN3bGNwMjdOdTZKekI2WStsZklVVHZpK281a1g3ZENjKzMycmIwNWNaY2FHaFZhR1FiLzBmTFZ2ME5MWkdycWdBd3B3MW1pUEhrbWFPTEtOOXIzL3doK0NzMVdoT2tidWg5ay9aUVVVdUI2NkZHYlZzMkwvcmdzaDI3Uk5zRVNOT1crVnpCeEQ1VzhCR3R5RC9tSDVHcWErL245WkhhWlM3UHZjb3Zvd01qOUt6TEdYMEozcEVqZFowZ1dXUVdSQTh6SG9iTEFlK3NYRTRDKy9nb3VnMHBpNkpTY0pqaFFCbzZnYkQ0L0F0U0k2V0d3RW51bDJCRnVMR1hjUFZpQXZhSWpGaWV0ZGVuMWNIK3A5c2tkMXN0VHlrSVlFY09jVHNFYXQrMHZGSVk1UjlqWVkyb2s3KzE0VHBOemNoOWJYS3VqUnRBN0tWS1JOaDgreFNXZ2d2R1lwRy9NeldoRkFwK0pFRmZwV1ZvVlYzajlTVHJFcEpvNjJWOGwwbkh2VGgxTW5IRDdtWlVybHVFb1o2RDNKNmQ5VHBBVjVWSkNsb2lrcmlJcnQ1VjhnYzNpUkRsWHl1S2VKRURyZzkxWmhmZU43MVVhYkU1M0t2YU9KRXpGa2RzN1hIM3pBVWZmaGMwS0JiamtXZTNXU1ZobTI2ZFZ0aEEzY3NoRVAzem5hNGJZYStLbDVpVm5tcHlJamdGZ2RFdFNOeDJIRFBNemtlZU5pWmtwKzl2Wjhqc1d3bEFPUkRwVWVXRDRTbHJja1p2RjhjbFdTM04vVDcrMSt2VXp4Yllzemg4VjBicnZ2SjVHdElMOXhhMlJ3b2pNNzVtV3JKbzlRTjlZa3JVQVhyd0VlOGtKellwUFQyQVZ0UXhjc200OFdwZFArSGN2ODlhRnd2NWpNRTNBVVpDeU9LaUsyTkc4WVEwZitVUi9neDdPMHkzVzR5cnc4M1pEQ0tvbkhuazJFOHVGTmZWc2hNTUtwSGkxQ0tUbnBITkZSdmpOSHMwZHB1TkpnVVYrZzd3UUpxT0FuRzVneFJPVGsyRkRlZ05qNHFSN1grSGYrUXpFUkpXR2V5REFReGNQbk13VjBNT0tYM1JIMXAyQXA1L2l5T1pBYU9sYTB2VVNFYXJYN0xtazJURTJSWnBuUVlPNmlVYnhUSmk3TnBBWExwSjNQbFRSN1gwRmdYYy9vSGJUbzZobkpCQ3ZvQnhwaUNMS3pDOTBGS21hMXNVN05oQklmTmR5K0UyZUM4SlA3VElvSmsyWml3aTR5Q0tmU0VzZ3lNUVZUaGdPZm9FcW5YQU04K1h4RmQ0aDhvSlpmNW5zNHhPOXI1QzZJQjNpNThzMUpEOE85WEtSK0diQWdETW0rNWFBOURkRW5JOGdkY3BBUHVaaFlPQUlPMFdxNW5ZdVA0cnRlaEhEZjlzaTUzOG5UZFVuOFNYaTl0ZzBhTWFmYnIvd2JHQUYrWnR4ZE1NeGZVNmppazJCdDl5UzlSMFBNSmxDNG43NXU1UzJ1RlNQYlRNRUpHdnVSTGNTUm1PenB1bmpYZURMSHZmYVArRkQrMkZyd21MRi9DdElydXlQYkFQallSamc2QzhYdG1KVTdnaGFkSzB0amt1ZU9zQVpTTjN1WFpRdS83U25QWXFlYUhaMC9NbzRVYW9DaDljQjlidkFXakxOL2hBVVlxendtZDF6VVdkblc4U2Q4TEl5aFVvN0xKdGZzak9KS3RmSHZZRTlFbDNEQnVYaUc0Q0FOUWxLTWpLdzBIRlFPYzVFMUhoMG1zRUw1djZJejVacW5uUThWMDY1d2sxK1F5bU84TG9oU1E2OCtvM1VJbTZ5N24ybGJSTTlGcGdrOEN3R2NMcHdaWkdYbTU3WTNmUzFsWElaS1dDYnF0NzErN3RoVCt2UWNYSFNEOExmSXA4UDUrS2IveG9sZVowd1grR0pqN3pQaTZYdWVlRUpjekFvTXBjYTVCZ1dNbkRyMzh2UXRVQVJPaldoOWxlOGpFVnZSckQyei95ZEo2NnNwOC9xZUJUL015K3ZpQTdneHFMTFl0anBUbkNTYzdyTFpPVEQzQ1dpYUI5L1d6VXFLSU9EQ1RnSGVnWWJuN1lNLytsNGl1VFdxNjZQL3hJSEdiRDFxSExtYS9PMFdBN1FPSHd3ajZiTEN0NHZnQ3hKaXovcmt2QkhnT29COFhNMFl1NjlDaXhsaFFoL2RxWUlGeVZFL0UrMUMvWE1aTXFEcXdVUGZmUnFMRm1YbldSdkxDY1A5TGFMcFZMY1U1aHc4UjJuSFhLWWlkTFRzM2FTb0xXbkNqNHVOUjhKdDhTaEFSdnp0d0RMOXppMDIwbGxBakF4dWFPVXg3OTlpUzRhWStJYU8vR3pBRDhuU1Y0UWhVRkRHSEZvSUdrNVFLb2tub00vTGxkT1ExTkJBbDdCQ2VxbmJmdS92Mkc5bTR6TFl1ZmFONy9wQ2tzTThXQUZtczZ3TWVlNXBjNi9hYVd5bDFnZElCdDB3NUh5UU1nMzIzQ3J3RGhpY1RndmFhQ1pCV2NKVDNpMDlHbUQzTlVKaVpjTjJrWXVHeC9aTFI0SURtMmtUUG5JcHZXN0xibEZsQ2ozYllDWEU1WWpkdStkU0d1dzdzZlRBQmx5Rm5TZlB4RDZCalVpYXJtYzNMTU4zSDUzQ0R1aDRWT1NMYS9aanpMQ3RjdWZZTm0zaXRoYlFVdWtjOE1NRXEvaXNTVmlrT1FUQ29iVGJaM2lyNzBoNEdmc1A3bytJcDRLM081dkpTSlR4ZjBNSGlpNTA3Vk1mQzJNcXVUeFhsRDVpOHlrNHl6UkdscU43SkJpdVN5MytpN3NYaXNyZFJPZWMvOW5DT25TTkRobmhoSXlZVzZCU3VzV0U4MTZlU3p2TjNRd3FLZkhpd3ZoQ3NwN0w0aU1vSFdUL3BMVTVyQzc3R0ZqNERiRmdnWXp5MXQxd3ZjcnU5TlRFcDlzZXZGUXFKbGp1anFZdXJTbjFZbENjVk56Z1VFREttOEpKVjJKVGFuY0NObUZqL3R6VThsdW90ZDFZY2t4bDlaNjloMG04aStyTGkxZWZGUURja0NjV3M2ZUR6WTRDWGZNOXJZbUUxdVhId3VMWVkzeHc1dzJjRmxQYlZCZmxYWXdhL2E0ZUFJRlNIYjhkNTZyWG45N09KUEc1SW55SFdicGRDTGNYaGRSWFhYUXdxVzJld2FOY21sUDNBMUVWRTRHZ2hacklPcHhRdWE1WFdHaEplTXFTU0FsQktFREVKWjJSbkg2SUhZWExONXBkcE4vQ2gyVEZweEg5b0dJSkFwTmFsbTRhZWwyQTE5cUJkWVR0RHdubGxySlVNTTNuaFNOL0JtdnJYRGFONm5JQmVXRGdCU2RpQnVPOFVNWnR2L2ZwNno5Q0pVbkh4MmlocDZUTTdkSWVCN0tmNUQvdkJkSFgwMDN0cUNxQ3huMGtsb0lvcnZUaStoT2ZSTVhkU2pldmFvVWdPWHRLbkxyY3hjVWlLVjJHa09JbmdwVGpIRDR6dkRPNVRHV3dneGVnYWVsL1dsUEEzeFlFRFJDdFB4N0UrZVV0NWFNSzFITE5GbXg3R043R0tPcmt2a01KMWFRS2xSMUtJZnJWQU5zVmdCUkhmRkF3bXlCYzhZaHBmNnFaTWN5MlVqYnYzOXhHbGxXbDNiMXlNajIxMkdkSHRvMExwc1RDcmx6MXNScmVsTGJqcHgzcmZObUNMTzVrNDJMWHU2TTgvWUE2WkpNUmxYMTg4RkVhWHFRUjNzNDhiRTBSRVR5MFJFcGxFN1J0N0dLNGsrZmJuSHNEc2t3VFZNWmxVblFUU2NCc3dPTjVIUWFHc212TUlTaWVyakJLcFk2Ukh5NlpheEEyd01LTmljcWFTc3ZuN0ZaZk52cGN2TGlDcXh6d1ZLZmdhbEJ1MEhBRkpUQjN3UHhrbEtMWnZQcElqSWZ5VUFvdnRFV1VIMExOVGYydlpzMXhTaDdESVJOdG44VksxWGphRzd5bEVNZldvTnJkbHJXc0JlcE4yMVRFV2p0UDVsTDRiQVQ2Rm1vUm5UcU5KTHYrTmt0bWVJQ0xJVjFvOUVDYTRIcStjU0NZNzhaNUxSeCtLMDE4Z2dVcStvaFlhWkEzREVlcHpvenNEYWIrMTNZWG5BcnVNbTVwMHRYU09mWm1mUXYyb1VlUE96K1owM2RDSDBjVm1BL2h1eFNPNDBoN0dId0xkSU1EcGhUcWVSSExLSTFoTm9VRXBGZWVqYzFQVmxINkVqdTNBamt5T1g3T3ZBRnM1OFBPemNIV0ZGMEVzbG0yUXBJSUh4SzMyVVRneGtQTFlSTHVDVytHVThkMVh1L1EybVVaUENlUFdoOGwvbEdCQm54V0xjTjRlejdxYWpKRTdaSm9aRlJqZ01XYXlaS0szWURyZU1GbXZVOUU1MlpIQ2xJZUhzMlZMb1JLeG5NUjI0bTlSOEVBb0VWaHJad3BwaHFwdTc1NWFEV0FzNHNURFZvaDB3SzNKWFFBcklreXI3OUhSWndDWWozMjNXcWJFOXdyd05TYm5haXJNZmdpWkhHQ1czS2dyRmliN3gzSFRyYldRaW9XWmYydUZMMG1qQ0ZINHMzblFGZWs2YzArZ2JyUlRVQW9PbXpZOFNCWng4YU1DZUtFbXhjWHp4c2V4Ym1FbGlybUpUUUpBaExVTXpSRHdjMFR2N3lzcEZNb1BQWDluVVRSeU54QVExaXExU0hmazVwUithcGZLMTJqWXNtaU0vYWlTY2M1KzYvL1NkUUJJMngvcmFJWUROcVIvUGtTQUdZR1k4V29oSENLSGlJQjlSZitBVURwUVF6eUtnQm5Kb0d2cnhOcHUxMENoay9pNG1OR0VLUTBzbFoyV2JvbzlrQ2VCcERhSVFxS1hiY2s2UjJaMDB6U25XTWRjb1VWZ21nOS9rbFhNUEZaK0FCdzZBcXVObmk1T1lYQzMzQjRhNDFoTTF5MDJUb3BScUZhZm5LYXlOcDdvR3NMSDBsYkI2aUNnTHpyNWlGNHdVOVRkeGp3NjhzZnYyS0pvS2RLdmtXNzJSV2hTcWdkU0RBM1BDMXdOVFhmYjkxSjYwMTVmWjFXZHVNWjJYSWE4ZW5nSUxSY1dtaXltTFBJdUZTYTVXWVdvSFc5TUZiQTg0a2xtWjZyNlQwRjZSbEk4L2hhcGp3VXUrcyt4N3hTVFVERnQzOFk1eTBiSmgvZ051L3J1SE5JaE5oSXpMaENyTlYxNWdNSWFQNmtmOGhtYmZjTmUyaC8rSHJ6bldDSDFKbnNkV1dRMmJ2QlE3Q1lEc1Y1Vmh1QUtRZHhRd3RYNThkZmVrNDU5aUdPcGNVOW10UEVsZXlKL1BDZEFoakxLMEUwelV6NVYyekozb2gyT2FkMC9rUUU0Vk5oNDR3bk0wOXhOdU1pUVhxVE5PaWdNeEJwaDh4dHNTOGY5d1RldUJaNUsxREdFaHJ3UWxiWC9VMDF3YVY3blFoaE5icnRWVUd3RW1MTEN2MFBlZ3ZWL1dGWXp5bFJTaGdZNXdyRC9hMmtDU21BSGJSc3o4aTY0VU5DUjVOTWVraldtdndlY0NEQlFFcDlWaXBSTWNwampZb2JxQ0w2WU00WU9NM2MxaVJtMm9kZlBZU2liczNyMWFxZ0x6U2hBUkE2TlNXZW9xU2pUUVNnQzJ4SC9rNzc1UmtZV1BLbTJrNEk3bmJ2czVWdloxNlZFT1FHSllsb2ZyV1BIeDJGM0h3amErdUl4VzQ5MFZBUzJ2NFhxelk0ZUR2VHU5S2wyWG1uUE8zMTNIT0x1eXpKc1dJNUFYUXRSem1PZHcvemRNemRsdEFRR1NSbU5FYlgwbDZLUFVtMExoQzQ2WEhhNTdIekQydmZ4dFBMby82TnI5UENBNzh0YUlEQ0xRRWZycFVvTy9JUTlFYTlnNkFHcVNDT0JmOEM5K0puYVJqcG9lbEpPK1Y5YUNBZ3U5ME0yU3hHb2lON1hMMkZXT2xhUG5majlSaUJPNnpGOXNHZjBCUld5ZU1hNmVaSHkySnNlYTRKcVo2RjZOQ0dZNXpBOXFhcjYzN3hJeWc4UGRJclVkVU9oWm9QRitYZmx0aFQ2QUt3WjFaUjRacDAyVGx5UDhDbDBoZnoyZkFUME9yZkRYN3htaENpZE5tdnE2NHZ3aVRpTmVxLzBrMG5DcnkrS2plRHJnd2FnL3V4Y0FMTnZzUnpNL00wUVNRRjNwRmZybExGcGo3K3RXbEoyRmNXU3M5eGxrVnp6dEhzZXFrQ21DZ3IwRTg3MlkzbkRTelBQa1J0bmxSMklyZlZhYmF3MzlQbTBWUkFDV1lqYzgyTXExTlRpU3g3MzUxeFRQWTI3akJ3Qk1pRVJrY3NHWjVGdGpzbExlcjVrdUFneG05aUtxQi9sOTc1dTVXc0hQSjh1Q3J4cUZEWHBjWk5NZ052ZUxiOHdNUXhObWxkc3BJdkpHVmxDUzJrdkxtZC9GajRqVkFMSVhNbmFqdDVGUTk1RnRhUWtWRUJ2RHhmRER4TW96MllDU1Vybkh2MDZGNUh2NjBIMWVqeXFsNGU0Y0t3enI0VVdTMjhYNU1kNlhYdlA1NWpIbUxVc1lPMEpHVG0xVHp0OUdTY2trQUx4blNzVmg5M1JnOExyb1FCWkJqZ0crc0NJZUhLUC9qV1lRZXNzcWRYTk8zcHZ1WWsxS1d2NHlQNFBBcnJlc0xGdmcyUUpuVzdLNUV6amdhb3Z1MnArbW9SOFNURUw1S01KK0JIaXRwYjBDQ1pRYmVDZkp0cFA3VHlveVlMRW9qeEVxaTBhQ0NYdFZiNWVnZTFWUk8zQVNjN0xYeWZSZkJjMzdoaFFqUDdQSTlUcHRxSVBwY00yZGJtMjZpNnBUMXRDZXpRNllqYUQzcjZnK1VXbEIrTGNseDVvOTltZjJlWElsS2YvNysrdmFXVWRhYi9XSmp4bjM4YkwwN3ZOM1NOR1lVbWVzN04rbG1NOHFJVFhVUVhhTmZDMitya1V5WXZCTzZzWUM4NUFhTGFqanpSMXk2WXpCQi9yelQ0dGtTZm5nNmgyUW1JeW91Q1VCNXdTSThnUlgrdjZlOENySmFNRUdBbm5TcEF3dk5mS2lFNmh4VU1KOG1idVQ3VVB3ODFmTXNDYnVKY3U1NS9aSUk2S1JkbzFCVXhKbUYxTndrR0Vxd2lNallwdk9JT2oyV3dEYWlOT1BUbzBWamJwSzNiaWQyb1RLQmZ6M08veisxVyt1a293WS9qTEpRbzR6L3JwTU5MSThwcFFJWmxubnpadVlyVDVOU090WVZmZzB1TklNSFdBRHZKZ2pDTStKcTdKTVFHRXF5M1dlR0ZTYnZRWUNEZ205MXUya3BCaEFBMnFWbW54aVM5U25ENkE4NzhsRjJOcnpINzNwcndZWnNwZW11SGxpZitYYnFvNytHanlkRU1PZ0ZxaUlYSXVGdml5U1BLMzR3aGcyWWNzQzVhMnNicTgvcVpGd3ljaVEydEN6RHhHU2R3cmhIYkNUNmZpWFVsTy9JeUMzdDBCSWY1UTZRS1pmbWcrSXBVUGloRktXSWoycEo1NWZKelhGejhWL211WWFHOE9GbFp2VTRUTFFZRkVEUDNzazN6WDBRQTRmTU5KQW5UOHZ1Z1pKT3hJbXhzdmFZUmRkRmc2dE9XdVZBSHE2cVhGMHJGeWY4QnpSVDQ2MFc4aG9zcnRheDNVNlFzeVBBTGErVGpncS95aC9ocEt2RFM4eWNUdU1iWmhHbi81empuWEpES1RyeE1DTnhwMjJLbnYrNGhoVUhJUS9DUmZnV09HYnZBeUZaanFlM0k2RzBDeWFKam9JVFFVTVJKSWIvS0g3bzlBRlN5UnBONWVSc1ZHSmdXMGJQdENtUUQvRVd2N0tLeXE1OHk4cG1SZzRheFZveHlKWXlQcEVlSmNTdVVUN0ozK0wxc3Q4Y3ZmbWdqSmtJRzVZUXBXK2lwSkxkTnhVUG5FN0F6ZnNnWG82RGNaTWI5cFZ2dUVHOEFmQ1VNQWJwU0F4WmhhSGhjUXl3cUEwK0MvU1VVTW1kS29pdnpJMHgxdWZMMmtHOWUvcUVvNEFMd3hSNWx2TmMySVl3TmUzcXE1RnVFV0F4RUxJN0hqYzN5c1NPaDUvRUdVL0JYTkx5MnNMZUd2dTMwMlMxV21UTGthWkUyT1RZSU0xVzdSeTM1emRuTlFYN2I3cCtvcXJSVTZ5ZEIvZUVKd2YyRFJxYWFiSUhmeVdyQ21pK2lHUkExamdmeEVFVCtOTWxCVFBIVnVnTGFKMnpoUFJVMWczbkExTm9IWU5TYmhvb0RJRkp2T2N2dDEyOTZVbER5ZElaWnZTcm8rQ1NwOElBakNQTGFlRG5GWEQraDltUHdkRllzeDZWdnZjNlZIZWVvWEp2S25mUU52eHZGWXRXWXlZUmU3dUxSMEhVQXlFVzJkc1dsM3B4OGVuTFMzSnUrakVmaUEzNkxIWkplSitMcTdJdFFtVktEZGRJN1BmZFhtMlNtWDRicE9pck1CdmZLWVpEMTF5dkw4dlVMWFhOSjA1Myt3NzMreVVxUTl0Vmo4SDVHZjQzNWRsK1NyUnFGN3BCYXpaZTJNb3k5YjRpWDBRQUhkZGcxamFSekFjSE8vaTRvODNhN0NRMjRUbkdLNXBlZHJKYm91dz09IiwgIm1hYyI6ICJSaFh6R0h5MjRkTkNuaUt2YmtvM3VSN0Y4MjVrVEV1bExWS0EvMndnK2lJPSJ9"
DATA = json.loads(base64.b64decode(_DATA_B64).decode("utf-8"))


def load_vault(password):
    raw = _decrypt(password, DATA)
    return json.loads(raw.decode("utf-8"))


# ============================================================
#  Interface graphique (fenetre)
# ============================================================
def main():
    import tkinter as tk
    import tkinter.font as tkfont

    BG = "#0f1422"
    BG2 = "#171d2e"
    BG3 = "#1f2740"
    FIELD = "#0b0f1d"
    ACCENT = "#7c5cff"
    ACCENT2 = "#00d4ff"
    TEXT = "#e8ecf4"
    MUTED = "#8b95a8"
    DANGER = "#ff7585"

    root = tk.Tk()
    root.title("Coffre — Martin")
    root.geometry("1080x710")
    root.minsize(900, 580)
    root.configure(bg=BG)

    mono = "Menlo" if _has_font(tkfont, "Menlo") else "Courier"
    f_title = tkfont.Font(family="Helvetica", size=22, weight="bold")
    f_h = tkfont.Font(family="Helvetica", size=15, weight="bold")
    f_n = tkfont.Font(family="Helvetica", size=11)
    f_s = tkfont.Font(family="Helvetica", size=9)
    f_mono = tkfont.Font(family=mono, size=11)

    state = {"vault": None, "view": "vault", "cat": "all", "search": ""}

    def clear(w):
        for c in w.winfo_children():
            c.destroy()

    def mkbtn(parent, text, cmd, bg=BG3, fg=TEXT, font=f_s, padx=10, pady=4):
        b = tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg, font=font,
                      relief="flat", activebackground=ACCENT, activeforeground="white",
                      cursor="hand2", bd=0, padx=padx, pady=pady, highlightthickness=0)
        return b

    status = {"label": None}

    def flash(msg):
        if status["label"] is not None:
            status["label"].config(text=msg)
            status["label"].after(1600, lambda: status["label"].config(text="")
                                   if status["label"] else None)

    def copy(text):
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        flash("Copié ✓")

    # ---------- ECRAN DE VERROUILLAGE ----------
    def show_lock():
        clear(root)
        wrap = tk.Frame(root, bg=BG)
        wrap.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(wrap, text="🔐", bg=BG, fg=TEXT,
                 font=tkfont.Font(size=46)).pack()
        tk.Label(wrap, text="Coffre", bg=BG, fg=TEXT, font=f_title).pack(pady=(8, 0))
        tk.Label(wrap, text="Entre ton mot de passe maître", bg=BG,
                 fg=MUTED, font=f_n).pack(pady=(2, 18))
        pw = tk.Entry(wrap, show="•", width=26, font=f_n, bg=FIELD, fg=TEXT,
                      insertbackground=TEXT, relief="flat", justify="center")
        pw.pack(ipady=9)
        pw.focus_set()
        err = tk.Label(wrap, text="", bg=BG, fg=DANGER, font=f_s)

        def attempt(*_):
            try:
                v = load_vault(pw.get())
            except Exception:
                err.config(text="Mot de passe incorrect.")
                err.pack(pady=(12, 0))
                pw.delete(0, "end")
                return
            state["vault"] = v
            show_app()

        mkbtn(wrap, "Déverrouiller", attempt, bg=ACCENT, fg="white",
              font=f_h, pady=9).pack(fill="x", pady=(16, 0))
        tk.Label(wrap, text="Chiffré · hors-ligne · sur ton ordinateur",
                 bg=BG, fg=MUTED, font=f_s).pack(pady=(16, 0))
        pw.bind("<Return>", attempt)

    # ---------- APPLICATION ----------
    def show_app():
        clear(root)
        cats = {c["id"]: c for c in state["vault"]["categories"]}

        sidebar = tk.Frame(root, bg=BG2, width=240)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        main = tk.Frame(root, bg=BG)
        main.pack(side="left", fill="both", expand=True)

        # --- entete sidebar ---
        head = tk.Frame(sidebar, bg=BG2)
        head.pack(fill="x", padx=16, pady=(16, 8))
        tk.Label(head, text="🔐  Coffre", bg=BG2, fg=TEXT, font=f_h).pack(anchor="w")
        tk.Label(head, text="MARTIN", bg=BG2, fg=MUTED, font=f_s).pack(anchor="w")

        # --- bascule Coffre / Planning ---
        sw = tk.Frame(sidebar, bg=BG2)
        sw.pack(fill="x", padx=12, pady=(4, 10))
        btn_vault = mkbtn(sw, "🔐 Coffre", lambda: switch("vault"), pady=7)
        btn_plan = mkbtn(sw, "📅 Planning", lambda: switch("planning"), pady=7)
        btn_vault.pack(side="left", expand=True, fill="x", padx=(0, 3))
        btn_plan.pack(side="left", expand=True, fill="x", padx=(3, 0))

        # --- liste des categories ---
        cat_box = tk.Listbox(sidebar, bg=FIELD, fg=TEXT, font=f_n, relief="flat",
                             selectbackground=ACCENT, selectforeground="white",
                             activestyle="none", highlightthickness=0, bd=0)
        cat_box.pack(fill="both", expand=True, padx=12, pady=4)
        cat_index = []

        def fill_categories():
            cat_box.delete(0, "end")
            cat_index.clear()
            counts = {}
            for e in state["vault"]["entries"]:
                counts[e["category"]] = counts.get(e["category"], 0) + 1
            cat_box.insert("end", "  Tout  (%d)" % len(state["vault"]["entries"]))
            cat_index.append("all")
            for c in state["vault"]["categories"]:
                n = counts.get(c["id"], 0)
                if n == 0:
                    continue
                cat_box.insert("end", "  %s  %s  (%d)" % (c.get("icon", "•"), c["name"], n))
                cat_index.append(c["id"])
            # selection courante
            if state["cat"] in cat_index:
                cat_box.selection_clear(0, "end")
                cat_box.selection_set(cat_index.index(state["cat"]))

        def on_cat(_=None):
            sel = cat_box.curselection()
            if not sel:
                return
            state["cat"] = cat_index[sel[0]]
            render_main()

        cat_box.bind("<<ListboxSelect>>", on_cat)

        # --- pied : verrouiller ---
        foot = tk.Frame(sidebar, bg=BG2)
        foot.pack(fill="x", padx=12, pady=12)
        mkbtn(foot, "🔒  Verrouiller", lock, pady=7).pack(fill="x")

        # --- contenu principal ---
        def set_toggle_styles():
            btn_vault.config(bg=ACCENT if state["view"] == "vault" else BG3,
                             fg="white" if state["view"] == "vault" else TEXT)
            btn_plan.config(bg=ACCENT if state["view"] == "planning" else BG3,
                            fg="white" if state["view"] == "planning" else TEXT)

        def switch(view):
            state["view"] = view
            set_toggle_styles()
            render_main()

        def render_main():
            clear(main)
            set_toggle_styles()
            if state["view"] == "planning":
                cat_box.pack_forget()
                render_planning(main)
            else:
                if not cat_box.winfo_ismapped():
                    cat_box.pack(fill="both", expand=True, padx=12, pady=4, before=foot)
                render_vault(main)

        # ============ VUE COFFRE ============
        def render_vault(parent):
            top = tk.Frame(parent, bg=BG)
            top.pack(fill="x", padx=18, pady=(16, 8))
            tk.Label(top, text="🔎", bg=BG, fg=MUTED, font=f_n).pack(side="left")
            search = tk.Entry(top, font=f_n, bg=FIELD, fg=TEXT, relief="flat",
                              insertbackground=TEXT)
            search.pack(side="left", fill="x", expand=True, ipady=7, padx=(8, 8))
            search.insert(0, state["search"])
            st = tk.Label(top, text="", bg=BG, fg=ACCENT2, font=f_s)
            st.pack(side="right")
            status["label"] = st

            body = tk.Frame(parent, bg=BG)
            body.pack(fill="both", expand=True, padx=18, pady=(0, 16))

            list_frame = tk.Frame(body, bg=BG, width=300)
            list_frame.pack(side="left", fill="y")
            list_frame.pack_propagate(False)
            ent_box = tk.Listbox(list_frame, bg=FIELD, fg=TEXT, font=f_n, relief="flat",
                                 selectbackground=ACCENT, selectforeground="white",
                                 activestyle="none", highlightthickness=0, bd=0)
            ent_box.pack(fill="both", expand=True)
            ent_index = []

            detail = tk.Frame(body, bg=BG)
            detail.pack(side="left", fill="both", expand=True, padx=(16, 0))

            def filtered():
                q = state["search"].strip().lower()
                items = state["vault"]["entries"]
                if state["cat"] != "all":
                    items = [e for e in items if e.get("category") == state["cat"]]
                if q:
                    def m(e):
                        return any(q in str(e.get(k, "")).lower()
                                   for k in ("name", "username", "email", "url", "notes", "category"))
                    items = [e for e in items if m(e)]
                return sorted(items, key=lambda e: e.get("name", "").lower())

            def fill_entries():
                ent_box.delete(0, "end")
                ent_index.clear()
                for e in filtered():
                    icon = e.get("icon") or (cats.get(e["category"], {}) or {}).get("icon", "🔑")
                    ent_box.insert("end", "  %s  %s" % (icon, e.get("name", "")))
                    ent_index.append(e)
                if ent_index:
                    ent_box.selection_set(0)
                    show_entry(ent_index[0])
                else:
                    clear(detail)
                    tk.Label(detail, text="Aucune entrée", bg=BG, fg=MUTED,
                             font=f_n).pack(pady=40)

            def on_search(_=None):
                state["search"] = search.get()
                fill_entries()

            search.bind("<KeyRelease>", on_search)

            def on_entry(_=None):
                sel = ent_box.curselection()
                if sel:
                    show_entry(ent_index[sel[0]])

            ent_box.bind("<<ListboxSelect>>", on_entry)

            def add_row(parent2, label, value, secret):
                row = tk.Frame(parent2, bg=BG2)
                row.pack(fill="x", pady=4)
                tk.Label(row, text=label.upper(), bg=BG2, fg=MUTED, font=f_s).pack(
                    anchor="w", padx=12, pady=(8, 0))
                line = tk.Frame(row, bg=BG2)
                line.pack(fill="x", padx=12, pady=(0, 9))
                shown = {"v": not secret}

                def disp():
                    return value if shown["v"] else "•" * min(14, len(value))

                val = tk.Label(line, text=disp(), bg=BG2, fg=TEXT, font=f_mono,
                               justify="left", wraplength=380, anchor="w")
                val.pack(side="left", fill="x", expand=True)
                mkbtn(line, "Copier", lambda: copy(value)).pack(side="right", padx=(4, 0))
                if secret:
                    tb = mkbtn(line, "Afficher", None)

                    def tog():
                        shown["v"] = not shown["v"]
                        val.config(text=disp())
                        tb.config(text="Masquer" if shown["v"] else "Afficher")
                    tb.config(command=tog)
                    tb.pack(side="right", padx=(4, 0))

            def show_entry(entry):
                clear(detail)
                cat = cats.get(entry.get("category"), {})
                h = tk.Frame(detail, bg=BG)
                h.pack(fill="x", pady=(0, 10))
                tk.Label(h, text=entry.get("icon") or cat.get("icon", "🔑"),
                         bg=BG, fg=TEXT, font=tkfont.Font(size=26)).pack(side="left")
                ht = tk.Frame(h, bg=BG)
                ht.pack(side="left", padx=10)
                tk.Label(ht, text=entry.get("name", ""), bg=BG, fg=TEXT,
                         font=f_h).pack(anchor="w")
                tk.Label(ht, text=cat.get("name", entry.get("category", "")),
                         bg=BG, fg=ACCENT2, font=f_s).pack(anchor="w")

                fields = tk.Frame(detail, bg=BG)
                fields.pack(fill="both", expand=True)
                rows = []
                if entry.get("email"):
                    rows.append(("Email", entry["email"], False))
                if entry.get("username"):
                    rows.append(("Identifiant", entry["username"], False))
                if entry.get("password"):
                    rows.append(("Mot de passe", entry["password"], True))
                if entry.get("url"):
                    rows.append(("Lien", entry["url"], False))
                for ex in entry.get("extra", []):
                    rows.append((ex.get("label", ""), ex.get("value", ""),
                                 bool(ex.get("secret"))))
                if entry.get("notes"):
                    rows.append(("Notes", entry["notes"], False))
                for (lb, vv, sc) in rows:
                    add_row(fields, lb, vv, sc)

            fill_entries()

        # ============ VUE PLANNING ============
        def render_planning(parent):
            p = state["vault"].get("planning")
            head2 = tk.Frame(parent, bg=BG)
            head2.pack(fill="x", padx=18, pady=(16, 6))
            tk.Label(head2, text="📅  %s" % (p.get("title", "Planning") if p else "Planning"),
                     bg=BG, fg=TEXT, font=f_title).pack(anchor="w")
            st = tk.Label(head2, text="", bg=BG, fg=ACCENT2, font=f_s)
            st.pack(anchor="w")
            status["label"] = st
            if not p:
                tk.Label(parent, text="Pas de planning.", bg=BG, fg=MUTED,
                         font=f_n).pack(pady=30)
                return
            if p.get("daily"):
                banner = tk.Frame(parent, bg=BG3)
                banner.pack(fill="x", padx=18, pady=(0, 10))
                tk.Label(banner, text="🔁 TOUS LES JOURS", bg=BG3, fg=MUTED,
                         font=f_s).pack(anchor="w", padx=12, pady=(8, 2))
                tags = " · ".join("%s %s" % (d.get("icon", ""), d.get("label", ""))
                                  for d in p["daily"])
                tk.Label(banner, text=tags, bg=BG3, fg=TEXT, font=f_n,
                         wraplength=760, justify="left").pack(anchor="w", padx=12,
                                                              pady=(0, 10))
            # zone defilante
            canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
            sb = tk.Scrollbar(parent, orient="vertical", command=canvas.yview)
            inner = tk.Frame(canvas, bg=BG)
            inner.bind("<Configure>",
                       lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            win = canvas.create_window((0, 0), window=inner, anchor="nw")
            canvas.bind("<Configure>", lambda e: canvas.itemconfig(win, width=e.width))
            canvas.configure(yscrollcommand=sb.set)
            canvas.pack(side="left", fill="both", expand=True, padx=(18, 0), pady=(0, 16))
            sb.pack(side="right", fill="y")

            for day in p.get("days", []):
                card = tk.Frame(inner, bg=BG2)
                card.pack(fill="x", pady=5, padx=(0, 14))
                bar = tk.Frame(card, bg=day.get("color", ACCENT), height=4)
                bar.pack(fill="x")
                tk.Label(card, text=day.get("name", "").upper(), bg=BG2, fg=TEXT,
                         font=f_h).pack(anchor="w", padx=14, pady=(10, 4))
                for t in day.get("tasks", []):
                    tk.Label(card, text="   %s  %s" % (t.get("icon", "•"), t.get("label", "")),
                             bg=BG2, fg=TEXT, font=f_n, anchor="w").pack(
                        fill="x", padx=14, pady=2)
                tk.Frame(card, bg=BG2, height=8).pack()

        # init
        fill_categories()
        switch("vault")

    def lock():
        state["vault"] = None
        show_lock()

    show_lock()
    root.mainloop()


def _has_font(tkfont, name):
    try:
        return name in tkfont.families()
    except Exception:
        return False


if __name__ == "__main__":
    main()
