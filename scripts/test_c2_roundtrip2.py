"""ROUND_OPS も逆順にした場合の roundtrip テスト"""
import sys, numpy as np
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

S_np = np.frombuffer(open('doc/_migration_kit/c2_sbox.bin','rb').read(), dtype=np.uint8)
BASIS = open('scripts/c2_basis.bin','rb').read()
_C = np.zeros((8, 256, 64), dtype=np.uint8)
for pos in range(8):
    for val in range(256):
        acc = np.zeros(64, dtype=np.uint8)
        for b in range(8):
            if (val >> b) & 1:
                acc ^= np.frombuffer(BASIS[(pos*8+b)*64:(pos*8+b)*64+64], dtype=np.uint8)
        _C[pos, val] = acc

ROUND_OPS = [(0,2,1),(1,1,0),(1,0,1),(0,1,1),(2,0,1),(2,2,0),(2,1,0),(1,2,0),
             (2,1,1),(1,1,1),(1,2,1),(2,1,2),(1,1,2),(2,2,1),(1,2,2),(2,2,2)]

def _mix(op, wi, w0):
    if op == 0: return wi ^ w0
    elif op == 1: return (wi + w0) & 0xFF
    else: return (wi - w0) & 0xFF

def F_s(W, K, ops):
    W = [int(S_np[W[i] ^ K[i]]) for i in range(4)]
    x = W[0] ^ W[1] ^ W[2] ^ W[3]
    W[0] = int(S_np[x])
    W[1] = _mix(ops[0], W[1], W[0])
    W[2] = _mix(ops[1], W[2], W[0])
    W[3] = _mix(ops[2], W[3], W[0])
    return W

def ksched(k8):
    acc = np.zeros(64, dtype=np.uint8)
    for pos in range(8):
        acc ^= _C[pos, k8[pos]]
    return [list(acc[r*4:r*4+4]) for r in range(16)]

def c2_enc(data8, key8):
    """Encryption: K[0..15], ROUND_OPS[0..15], output R||L"""
    rks = ksched(list(key8))
    L = list(data8[:4])
    R = list(data8[4:])
    for r in range(16):
        oR = R[:]
        Fr = F_s(R[:], rks[r], ROUND_OPS[r])
        R = [Fr[i] ^ L[i] for i in range(4)]
        L = oR
    return bytes(R + L)

def c2_dec_v1(data8, key8):
    """Dec v1: reversed K, same ROUND_OPS order (current implementation = WRONG?)"""
    rks = ksched(list(key8))
    rks = list(reversed(rks))
    L = list(data8[:4]); R = list(data8[4:])
    for r in range(16):
        oR = R[:]
        Fr = F_s(R[:], rks[r], ROUND_OPS[r])
        R = [Fr[i] ^ L[i] for i in range(4)]
        L = oR
    return bytes(R + L)

def c2_dec_v2(data8, key8):
    """Dec v2: reversed K AND reversed ROUND_OPS"""
    rks = ksched(list(key8))
    rks = list(reversed(rks))
    ops = list(reversed(ROUND_OPS))
    L = list(data8[:4]); R = list(data8[4:])
    for r in range(16):
        oR = R[:]
        Fr = F_s(R[:], rks[r], ops[r])
        R = [Fr[i] ^ L[i] for i in range(4)]
        L = oR
    return bytes(R + L)

def c2_dec_v3(data8, key8):
    """Dec v3: same K order, reversed ROUND_OPS"""
    rks = ksched(list(key8))
    ops = list(reversed(ROUND_OPS))
    L = list(data8[:4]); R = list(data8[4:])
    for r in range(16):
        oR = R[:]
        Fr = F_s(R[:], rks[r], ops[r])
        R = [Fr[i] ^ L[i] for i in range(4)]
        L = oR
    return bytes(R + L)

def c2_dec_v4(data8, key8):
    """Dec v4: reversed K AND reversed ROUND_OPS, output L||R"""
    rks = ksched(list(key8))
    rks = list(reversed(rks))
    ops = list(reversed(ROUND_OPS))
    L = list(data8[:4]); R = list(data8[4:])
    for r in range(16):
        oR = R[:]
        Fr = F_s(R[:], rks[r], ops[r])
        R = [Fr[i] ^ L[i] for i in range(4)]
        L = oR
    return bytes(L + R)

def c2_dec_v5(data8, key8):
    """Dec v5: reversed K, ROUND_OPS[r] where r counts from 15 down → ops[15-r]"""
    rks = ksched(list(key8))
    rks_rev = list(reversed(rks))
    L = list(data8[:4]); R = list(data8[4:])
    for r in range(16):
        oR = R[:]
        Fr = F_s(R[:], rks_rev[r], ROUND_OPS[15 - r])
        R = [Fr[i] ^ L[i] for i in range(4)]
        L = oR
    return bytes(R + L)

k8 = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0x00])
pt = bytes([0x47, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
ct = c2_enc(pt, k8)
print(f"PT: {pt.hex()}")
print(f"CT: {ct.hex()}")
print()
for name, fn in [("dec_v1(rev_K,fwd_OPS)",c2_dec_v1),
                  ("dec_v2(rev_K,rev_OPS)",c2_dec_v2),
                  ("dec_v3(fwd_K,rev_OPS)",c2_dec_v3),
                  ("dec_v4(rev_K,rev_OPS,L|R)",c2_dec_v4),
                  ("dec_v5(rev_K,OPS[15-r])",c2_dec_v5)]:
    r = fn(ct, k8)
    match = "✓ MATCH" if r == pt else "✗"
    print(f"  {name}: {r.hex()}  {match}")

# Also test enc(enc(X)) == X (involution check)
ct2 = c2_enc(ct, k8)
print(f"\n  enc(enc(PT)): {ct2.hex()}  involution: {ct2==pt}")
