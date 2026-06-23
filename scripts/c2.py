# C2 (Cryptomeria) 実装。F関数は米国特許US9014370B2 Table1の逐語、S-boxは実機抽出(c2_sbox.bin)。
import os
S = open(os.path.join(os.path.dirname(__file__),"..","doc","_migration_kit","c2_sbox.bin"),"rb").read()
assert len(S)==256
M32=0xffffffff
def rol8(x,n): x&=0xff; return ((x<<n)|(x>>(8-n)))&0xff
def rol32(x,n): x&=M32; return ((x<<n)|(x>>(32-n)))&M32
def rol(x,n,bits):
    m=(1<<bits)-1; x&=m; return ((x<<n)|(x>>(bits-n)))&m
def F(data,key):
    t=(data+key)&M32
    v0=S[t&0xff]; v1=(t>>8)&0xff; v2=(t>>16)&0xff; v3=(t>>24)&0xff
    u=v0^0x65; v1^=rol8(u,1)
    u=v0^0x2b; v2^=rol8(u,5)
    u=v0^0xc9; v3^=rol8(u,2)
    t=((v3<<24)|(v2<<16)|(v1<<8)|v0)&M32
    t^=rol32(t,9)^rol32(t,22)
    return t&M32
def key_schedule(key56):
    rks=[]; tk=rol(key56,17,56)
    for r in range(10):
        if r>0: tk=rol(tk,34,56)
        kb=(tk>>32)&0xff
        sb=S[(r^kb)&0xff]
        rk=(((sb<<4)&M32)+(tk&M32))&M32
        rks.append(rk)
    return rks
def enc_block(blk, rks):   # blk: 8 bytes -> 8 bytes
    L=(blk>>32)&M32; R=blk&M32
    for r in range(10):
        if r%2==0: L=(L+F(R,rks[r]))&M32
        else:      R=(R+F(L,rks[r]))&M32
    return ((R<<32)|L)&0xffffffffffffffff
def dec_block(blk, rks):
    R=(blk>>32)&M32; L=blk&M32
    for r in range(9,-1,-1):
        if r%2==0: L=(L-F(R,rks[r]))&M32
        else:      R=(R-F(L,rks[r]))&M32
    return ((L<<32)|R)&0xffffffffffffffff
