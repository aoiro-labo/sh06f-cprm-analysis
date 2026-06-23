# 実C2(エミュレータ)のゼロ鍵出力を正解に、C2アルゴリズムのパラメータを同定する。
# ゼロ鍵 → 全ラウンド鍵=0 → F関数はS-boxのみで決定的。よって rounds/endian/Feistel/mode を総当たり可能。
import os, itertools
ROOT=os.path.join(os.path.dirname(__file__),"..")
S=open(os.path.join(ROOT,"doc","_migration_kit","c2_sbox.bin"),"rb").read()
assert len(S)==256

sb1=open(os.path.join(ROOT,"SD_VIDEO","PRG011","MOV001.sb1"),"rb").read()
CT=sb1[0xA0:0xA0+32]   # ct0..ct3
ct=[CT[i*8:i*8+8] for i in range(4)]
# エミュレータ(実コード,ゼロ鍵)の出力 out[:32]
OUT=bytes.fromhex("d1 04 2b 75 f1 c0 5b 1e 5b d8 76 34 3f 15 ad 62 1b d5 09 84 95 a8 42 ad 4b f3 5e 6f ae 1b 1d 5d".replace(" ",""))
out=[OUT[i*8:i*8+8] for i in range(4)]

def F(w):  # w: list[4] bytes, zero round key版(K=0)
    w=list(w)
    w=[S[w[0]],S[w[1]],S[w[2]],S[w[3]]]
    w[0]^= w[1]^w[2]^w[3]
    w[0]=S[w[0]]
    w[1]=(w[1]^w[0])&0xff
    w[2]=(w[2]-w[0])&0xff
    w[3]=(w[3]+w[0])&0xff
    return w

def feistel_dec(block8, rounds, swap_halves, fwd):
    # block8: 8 bytes. A=前半,B=後半(各4byte list)
    A=list(block8[0:4]); B=list(block8[4:8])
    if swap_halves: A,B=B,A
    rng = range(rounds) if fwd else range(rounds)  # ゼロ鍵は対称なので向きは関係薄いが一応
    for _ in range(rounds):
        Bf=F(B)
        newB=[(Bf[i]^A[i])&0xff for i in range(4)]
        A=B
        B=newB
    if swap_halves: A,B=B,A
    return bytes(A+B)

def test():
    found=[]
    for rounds in range(4,21):
        for swap in (False,True):
            for mode in ("ECB","CBC"):
                ok=True
                for i in range(1,4):  # ブロック1..3(CBCはIV不要)
                    dec=feistel_dec(ct[i], rounds, swap, True)
                    if mode=="CBC":
                        pt=bytes((dec[j]^ct[i-1][j])&0xff for j in range(8))
                    else:
                        pt=dec
                    if pt!=out[i]: ok=False; break
                if ok:
                    found.append((rounds,swap,mode))
                    print(f"  [MATCH] rounds={rounds} swap={swap} mode={mode}")
    if not found:
        print("  一致なし。F関数/Feistel構造が異なる可能性。block0生値で個別確認:")
        for rounds in (8,10,16):
            d=feistel_dec(ct[1],rounds,False,True)
            print(f"   rounds={rounds} ECB D(ct1)={d.hex(' ')}  CBC^ct0={bytes((d[j]^ct[0][j])&0xff for j in range(8)).hex(' ')}  target o1={out[1].hex(' ')}")
    return found

if __name__=="__main__":
    print("ct0..3:", [c.hex(' ') for c in ct])
    print("out0..3:", [o.hex(' ') for o in out])
    test()
