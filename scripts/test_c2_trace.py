"""C2 Feistel 1ラウンドトレース and roundtrip verification"""
import sys, numpy as np
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

S_np = np.frombuffer(open('doc/_migration_kit/c2_sbox.bin','rb').read(), dtype=np.uint8)
BASIS = open('scripts/c2_basis.bin','rb').read()
assert len(BASIS) == 64*64

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

k8 = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0x00])
rks = ksched(list(k8))
print("Round keys:")
for i, rk in enumerate(rks):
    print(f"  K[{i:2d}]: {bytes(rk).hex()}")

pt = bytes([0x47, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
print(f"\nPT: {pt.hex()}  L={pt[:4].hex()} R={pt[4:].hex()}")

# 1-round Feistel forward
L0 = list(pt[:4]); R0 = list(pt[4:])
Fr0 = F_s(R0[:], rks[0], ROUND_OPS[0])
L1 = R0[:]
R1 = [Fr0[i] ^ L0[i] for i in range(4)]
print(f"\n1-round enc:")
print(f"  F(R0, K0)    = {bytes(Fr0).hex()}")
print(f"  L1=R0        = {bytes(L1).hex()}")
print(f"  R1=F(R0)^L0  = {bytes(R1).hex()}")
CT1 = bytes(R1 + L1)
print(f"  CT(R1||L1)   = {CT1.hex()}")

# 1-round Feistel backward (decryption) - key reversed = same K[0] for 1 round
# Input: CT = R1||L1  → in code: L=R1, R=L1
L_in = R1[:]; R_in = L1[:]
print(f"\n1-round dec (input: L=R1={bytes(L_in).hex()}, R=L1={bytes(R_in).hex()}):")
Fr_dec = F_s(R_in[:], rks[0], ROUND_OPS[0])
L_out = R_in[:]
R_out = [Fr_dec[i] ^ L_in[i] for i in range(4)]
print(f"  F(L1, K0)    = {bytes(Fr_dec).hex()}")
print(f"  L_out=L1     = {bytes(L_out).hex()}")
print(f"  R_out=F^R1   = {bytes(R_out).hex()}")
print(f"  output R||L  = {bytes(R_out+L_out).hex()}  vs PT={pt.hex()}")

# The correct dec for 1-round Feistel is:
# R0 = L1; L0 = R1 XOR F(L1, K0)
# where output = L0||R0
R0_rec = L1[:]
L0_rec = [R1[i] ^ Fr_dec[i] for i in range(4)]
print(f"\n  Expected: L0={bytes(L0).hex()} R0={bytes(R0).hex()}")
print(f"  Got:      L0={bytes(L0_rec).hex()} R0={bytes(R0_rec).hex()}")
print(f"  Match L0: {bytes(L0_rec)==bytes(L0)}, Match R0: {bytes(R0_rec)==bytes(R0)}")
# the output in c2_run is bytes(R+L) = R_out||L_out
# here R_out=[Fr_dec^L_in]=L0_rec, L_out=R_in=R0_rec
# so output of c2_run for dec = L0_rec||R0_rec = L0||R0 = PT?
print(f"  c2_run output = R_out||L_out = {bytes(R_out+L_out).hex()}")
print(f"  PT            = {pt.hex()}")
if bytes(R_out+L_out) == pt:
    print("  1-round roundtrip: PASS!")
else:
    print("  1-round roundtrip: FAIL")
    print(f"  R_out={bytes(R_out).hex()}")
    print(f"  L_out={bytes(L_out).hex()}")
    print(f"  Note: R_out should be L0={bytes(L0).hex()}, L_out should be R0={bytes(R0).hex()}")
