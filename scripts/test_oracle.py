"""修正後の scan_correct.py の dec_bytes04_batch を検証"""
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

def _mix_v(op, wi, w0):
    if op == 0: return wi ^ w0
    elif op == 1: return (wi.astype(np.int16) + w0.astype(np.int16)).astype(np.uint8)
    else: return (wi.astype(np.int16) - w0.astype(np.int16)).astype(np.uint8)

def F_batch(W, K, ops):
    W = S_np[W ^ K]
    x = W[:, 0] ^ W[:, 1] ^ W[:, 2] ^ W[:, 3]
    W[:, 0] = S_np[x]
    W[:, 1] = _mix_v(ops[0], W[:, 1], W[:, 0])
    W[:, 2] = _mix_v(ops[1], W[:, 2], W[:, 0])
    W[:, 3] = _mix_v(ops[2], W[:, 3], W[:, 0])
    return W

def ksched_batch(keys8):
    acc = np.zeros((len(keys8), 64), dtype=np.uint8)
    for pos in range(8):
        acc ^= _C[pos, keys8[:, pos]]
    return np.stack([acc[:, r*4:r*4+4] for r in range(16)])

def c2_enc_batch(pt8, rks):
    """Encryption: fwd keys, fwd ROUND_OPS"""
    N = rks.shape[1]
    L = np.tile(pt8[:4], (N,1)).astype(np.uint8)
    R = np.tile(pt8[4:], (N,1)).astype(np.uint8)
    for r in range(16):
        oldR = R.copy()
        Fr = F_batch(R.copy(), rks[r].copy(), ROUND_OPS[r])
        R = Fr ^ L
        L = oldR
    return np.concatenate([R, L], axis=1)  # R||L

def dec_bytes04_batch(ct8, rks):
    """Decryption FIXED: rev keys AND rev ROUND_OPS"""
    N = rks.shape[1]
    L = np.tile(ct8[:4], (N,1)).astype(np.uint8)
    R = np.tile(ct8[4:], (N,1)).astype(np.uint8)
    for r in range(16):
        oldR = R.copy()
        Fr = F_batch(R.copy(), rks[15-r].copy(), ROUND_OPS[15-r])
        R = Fr ^ L
        L = oldR
    return np.stack([R[:,0], L[:,0]], axis=1)

# テスト: 既知の平文/暗号文でラウンドトリップ
# 複数のテストキーと平文
test_cases = [
    (bytes([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0x00]),
     bytes([0x47,0x01,0x02,0x03,0x04,0x05,0x06,0x07])),
    (bytes([0xFF,0xFE,0xFD,0xFC,0xFB,0xFA,0xF9,0x00]),
     bytes([0x47,0x40,0x00,0x10,0x00,0x00,0x00,0x00])),  # typical TS header
    (bytes([0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0x00]),
     bytes([0x00,0x00,0x00,0x00,0x47,0x40,0x00,0x01])),  # M2TS: 4B timestamp + TS
]

all_pass = True
for k8, pt8 in test_cases:
    keys = np.array([list(k8)], dtype=np.uint8)
    rks = ksched_batch(keys)
    ct_arr = c2_enc_batch(np.frombuffer(pt8, dtype=np.uint8), rks)
    ct8 = ct_arr[0]
    dec_b04 = dec_bytes04_batch(ct8, rks)
    byte0 = dec_b04[0, 0]
    byte4 = dec_b04[0, 1]
    exp0 = pt8[0]
    exp4 = pt8[4]
    ok = (byte0 == exp0) and (byte4 == exp4)
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] K={k8.hex()} PT[0]={exp0:02x} PT[4]={exp4:02x} → dec[0]={byte0:02x} dec[4]={byte4:02x}")
    if not ok:
        all_pass = False

print()
if all_pass:
    print("全テスト PASS: C2 復号が正しく動作している")
else:
    print("FAIL あり: まだバグが残っている")
