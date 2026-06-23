# エミュレータで decrypt() を命令トレースし、Feistelの実構造を経験的に確定する。
import os, struct
from unicorn import *
from unicorn.x86_const import *
import c2lib as L

def trace(key8, block8):
    uc=L._mk()
    uc.mem_write(L.KEY, key8.ljust(8,b'\0')[:8])
    uc.mem_write(L.BUF, block8)
    esp=L.STACK+0x80000
    for v in reversed([L.KEY, L.BUF, len(block8)]):
        esp-=4; uc.mem_write(esp,struct.pack("<I",v))
    esp-=4; uc.mem_write(esp,struct.pack("<I",L.SENT))
    uc.reg_write(UC_X86_REG_ESP,esp)
    EBP=L.STACK+0x90000
    uc.reg_write(UC_X86_REG_EBP,EBP)

    Fcalls=[]   # (target, Wptr, Kval, retInBody)
    def hk(u,a,size,d):
        if a==L.SENT: u.emu_stop(); return
        if 0x36013a00<=a<0x36014a00:           # 16ラウンドのF変種(0x36013a05..0x36014950)
            code=bytes(u.mem_read(a,3))
            if code==b"\x55\x8b\xec":          # push ebp; mov ebp,esp = 関数入口
                sp=u.reg_read(UC_X86_REG_ESP)
                ret=struct.unpack("<I",u.mem_read(sp,4))[0]
                W=struct.unpack("<I",u.mem_read(sp+4,4))[0]
                K=struct.unpack("<I",u.mem_read(sp+8,4))[0]
                Kval=bytes(u.mem_read(K,4)) if 0x10000000<=K<0x40000000 else b'????'
                Wval=bytes(u.mem_read(W,8)) if 0x10000000<=W<0x40000000 else b'????'
                Fcalls.append((a,W,Kval,ret,Wval))
    uc.hook_add(UC_HOOK_CODE,hk)
    try:
        uc.emu_start(L.DEC, L.SENT, count=5000000)
    except UcError as e:
        print("UcErr",e, hex(uc.reg_read(UC_X86_REG_EIP)))
    # ラウンド鍵領域 [ebp-0x44]
    rk=bytes(uc.mem_read(EBP-0x44,64))
    out=bytes(uc.mem_read(L.BUF,len(block8)))
    return Fcalls, rk, out

def rkseq(key):
    """復号順のラウンド鍵 10*4=40バイトを返す。"""
    Fcalls,_,_=trace(key, bytes(8))
    return b"".join(f[2] for f in Fcalls)

def test_linear():
    A=bytes.fromhex("0102030405060708")
    B=bytes.fromhex("1000000000000000")
    AB=bytes(a^b for a,b in zip(A,B))
    rA,rB,rAB=rkseq(A),rkseq(B),rkseq(AB)
    xor=bytes(x^y for x,y in zip(rA,rB))
    print("rk(A)  =",rA.hex())
    print("rk(B)  =",rB.hex())
    print("rk(AB) =",rAB.hex())
    print("rk(A)^rk(B)=",xor.hex())
    print("線形(XOR一致)?:", xor==rAB)
    # ゼロ鍵が全0かも確認
    print("rk(0)=",rkseq(bytes(8)).hex())

def show(key, blk, label):
    Fcalls, rk, out = trace(key, blk)
    print(f"\n### {label}  key={key.hex()} blk={blk.hex()}")
    print(f"F入口数(=ラウンド数): {len(Fcalls)}")
    for i,(tgt,W,Kval,ret,Wval) in enumerate(Fcalls):
        wh = 'buf+4' if W==L.BUF+4 else ('buf+0' if W==L.BUF else hex(W))
        print(f"  r{i:2d}: F@{tgt:#x} W={wh} Win={Wval.hex()} rk={Kval.hex()}")
    print("out:", out.hex(' '))
    rkseq=[f[2].hex() for f in Fcalls]
    print("round-key列:", rkseq)

if __name__=="__main__":
    show(bytes.fromhex("0102030405060708"), bytes.fromhex("1122334455667788"), "nonzero key")
    show(bytes(8), bytes.fromhex("0000000000000000"), "zero key, zero blk")
