# 高速Python C2。鍵スケジュールは線形(基底64ベクトルのXOR)、Feistelは実コードからトレース確定(10R)。
import os, sys
ROOT=os.path.join(os.path.dirname(__file__),"..")
S=open(os.path.join(ROOT,"doc","_migration_kit","c2_sbox.bin"),"rb").read()
BASIS_PATH=os.path.join(os.path.dirname(__file__),"c2_basis.bin")

def gen_basis():
    """エミュレータで各入力ビットに対する復号順ラウンド鍵(40B)を採取 → 64*40 を保存。"""
    sys.path.insert(0,os.path.dirname(__file__))
    import c2_trace as t
    rows=[]
    for bit in range(64):
        key=bytearray(8); key[bit//8]|=(1<<(bit%8))
        rows.append(t.rkseq(bytes(key)))
        print(f"  basis bit {bit}/64", end="\r")
    data=b"".join(rows)
    open(BASIS_PATH,"wb").write(data)
    print("\nbasis saved", len(data))
    return data

def load_basis():
    if not os.path.exists(BASIS_PATH): return gen_basis()
    return open(BASIS_PATH,"rb").read()

RKLEN=64   # 16ラウンド * 4バイト
_BASIS=None
def key_schedule(key8):
    """key8(8byte) -> 16個の4byteラウンド鍵(復号順)。線形: 立っているビットの基底をXOR。"""
    global _BASIS
    if _BASIS is None:
        b=load_basis(); assert len(b)==64*RKLEN, f"basis len {len(b)} != {64*RKLEN} (再生成要)"
        _BASIS=[b[i*RKLEN:i*RKLEN+RKLEN] for i in range(64)]
    acc=bytearray(RKLEN)
    for bit in range(64):
        if key8[bit//8]>>(bit%8)&1:
            row=_BASIS[bit]
            for j in range(RKLEN): acc[j]^=row[j]
    return [bytes(acc[r*4:r*4+4]) for r in range(16)]

# ラウンド別F変種の末尾3演算(W1,W2,W3 を W0で混合)。実コード(0x36014xxx)からトレース順に抽出。
# X=xor, A=add, S=sub
ROUND_OPS=[
 ('X','S','A'),  # r0  F@0x36014950
 ('A','A','X'),  # r1  F@0x3601484b
 ('A','X','A'),  # r2  F@0x36014746
 ('X','A','A'),  # r3  F@0x36014641
 ('S','X','A'),  # r4  F@0x3601453c
 ('S','S','X'),  # r5  F@0x36014437
 ('S','A','X'),  # r6  F@0x36014332
 ('A','S','X'),  # r7  F@0x3601422d
 ('S','A','A'),  # r8  F@0x36014128
 ('A','A','A'),  # r9  F@0x36014023
 ('A','S','A'),  # r10 F@0x36013f1e
 ('S','A','S'),  # r11 F@0x36013e19
 ('A','A','S'),  # r12 F@0x36013d14
 ('S','S','A'),  # r13 F@0x36013c0f
 ('A','S','S'),  # r14 F@0x36013b0a
 ('S','S','S'),  # r15 F@0x36013a05
]
def _mix(op,wi,w0):
    if op=='X': return wi^w0
    if op=='A': return (wi+w0)&0xff
    return (wi-w0)&0xff
def F(W,K,ops):
    W=[W[0]^K[0],W[1]^K[1],W[2]^K[2],W[3]^K[3]]
    W=[S[W[0]],S[W[1]],S[W[2]],S[W[3]]]
    W[0]^= W[1]^W[2]^W[3]
    W[0]=S[W[0]]
    W[1]=_mix(ops[0],W[1],W[0])
    W[2]=_mix(ops[1],W[2],W[0])
    W[3]=_mix(ops[2],W[3],W[0])
    return W

def dec_block(block8, rks):
    # 正しい C2 復号: 鍵を逆順、ROUND_OPS も逆順
    # test_c2_roundtrip2.py dec_v2 で検証済み
    L=list(block8[0:4]); R=list(block8[4:8])
    for r in range(16):
        oldR=R
        Fr=F(R, rks[15-r], ROUND_OPS[15-r])
        R=[(Fr[i]^L[i])&0xff for i in range(4)]
        L=oldR
    return bytes(R+L)

def dec_ecb(ct, key8):
    rks=key_schedule(key8)
    out=bytearray()
    for i in range(0,len(ct)-7,8):
        out+=dec_block(ct[i:i+8], rks)
    return bytes(out)

if __name__=="__main__":
    rks=key_schedule(bytes.fromhex("0102030405060708"))
    print("rks(16):", [r.hex() for r in rks])
    d=dec_block(bytes.fromhex("1122334455667788"), rks)
    print("dec_block:", d.hex(), "expect f900170697e51fb0", "OK" if d.hex()=="f900170697e51fb0" else "NG")
    # ECB検証: ゼロ鍵 .sb1[0xA0:] → emu d1042b75...
    sb1=open(os.path.join(ROOT,"SD_VIDEO","PRG011","MOV001.sb1"),"rb").read()
    enc=sb1[0xA0:0xA0+32]
    pt=dec_ecb(enc, bytes(8))
    print("ecb zero:", pt.hex(' '))
    print("expect  :", "d1 04 2b 75 f1 c0 5b 1e 5b d8 76 34 3f 15 ad 62 1b d5 09 84 95 a8 42 ad 4b f3 5e 6f ae 1b 1d 5d")
