import sys, numpy as np
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
S_np = np.frombuffer(open('doc/_migration_kit/c2_sbox.bin','rb').read(), dtype=np.uint8)
BASIS = open('scripts/c2_basis.bin','rb').read()
_C = np.zeros((8,256,64), dtype=np.uint8)
for pos in range(8):
    for val in range(256):
        acc = np.zeros(64, dtype=np.uint8)
        for b in range(8):
            if (val>>b)&1:
                acc ^= np.frombuffer(BASIS[(pos*8+b)*64:(pos*8+b)*64+64], dtype=np.uint8)
        _C[pos,val] = acc

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

def c2(data8, key8, rev=False, out_rl=True):
    rks = ksched(list(key8))
    if rev:
        rks = list(reversed(rks))
    L = list(data8[:4])
    R = list(data8[4:])
    for r in range(16):
        oR = R[:]
        Fr = F_s(R[:], rks[r], ROUND_OPS[r])
        R = [Fr[i] ^ L[i] for i in range(4)]
        L = oR
    return bytes(R + L) if out_rl else bytes(L + R)

k8 = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0x00])
pt = bytes([0x47, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])

ct_fwd_rl = c2(pt, k8, rev=False, out_rl=True)
ct_fwd_lr = c2(pt, k8, rev=False, out_rl=False)
ct_rev_rl = c2(pt, k8, rev=True, out_rl=True)
ct_rev_lr = c2(pt, k8, rev=True, out_rl=False)

print(f'PT:           {pt.hex()}')
print()
print('=== 4パターン enc ===')
print(f'enc(fwd,R|L): {ct_fwd_rl.hex()}')
print(f'enc(fwd,L|R): {ct_fwd_lr.hex()}')
print(f'enc(rev,R|L): {ct_rev_rl.hex()}')
print(f'enc(rev,L|R): {ct_rev_lr.hex()}')
print()
print('=== roundtrip: dec(enc(PT)) == PT? ===')
enc_variants = [
    (ct_fwd_rl, 'fwd_rl'),
    (ct_fwd_lr, 'fwd_lr'),
    (ct_rev_rl, 'rev_rl'),
    (ct_rev_lr, 'rev_lr'),
]
for ct, enc_name in enc_variants:
    for rev2 in [False, True]:
        for rl2 in [True, False]:
            r2 = c2(ct, k8, rev=rev2, out_rl=rl2)
            if r2 == pt:
                mode = 'rev' if rev2 else 'fwd'
                outp = 'R|L' if rl2 else 'L|R'
                print(f'  MATCH: enc={enc_name}  dec=({mode},{outp}) -> {r2.hex()}')

print('done')
