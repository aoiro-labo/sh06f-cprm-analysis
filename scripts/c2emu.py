import struct
from unicorn import *
from unicorn.x86_const import *
DMP="SD-MobileImpact.exe.dmp"
_d=open(DMP,"rb").read()
sig,ver,ns,dirrva,_,_=struct.unpack_from("<4sIIIII",_d,0)
_st={}
for i in range(ns):
    s,sz,rva=struct.unpack_from("<III",_d,dirrva+i*12); _st[s]=(sz,rva)
sz,rva=_st[9]; nmem,base=struct.unpack_from("<QQ",_d,rva); off=base; p=rva+16; _ranges=[]
for i in range(nmem):
    s,z=struct.unpack_from("<QQ",_d,p);p+=16; _ranges.append((s,z,off)); off+=z
def read_va(va,n):
    out=bytearray()
    for k in range(n):
        b=0
        for s,z,fo in _ranges:
            if s<=va+k<s+z: b=_d[fo+(va+k-s)]; break
        out.append(b)
    return bytes(out)
MODBASE=0x36000000; MODSIZE=0x40000
DEC=0x36012cec
def make_uc():
    uc=Uc(UC_ARCH_X86,UC_MODE_32)
    uc.mem_map(MODBASE,MODSIZE)
    uc.mem_write(MODBASE, read_va(MODBASE,MODSIZE))
    uc.mem_map(0x100000,0x200000)   # stack+buffers区
    return uc
SENT=0x300000
def decrypt(key8, data):
    uc=make_uc()
    uc.mem_map(SENT,0x1000)
    KEY=0x140000; BUF=0x160000
    uc.mem_write(KEY, key8.ljust(8,b'\0'))
    uc.mem_write(BUF, data)
    esp=0x2f0000
    ln=len(data)
    for val in (ln, BUF, KEY, SENT):  # push len,buf,key,sentinel(ret) 逆順
        esp-=4; uc.mem_write(esp,struct.pack("<I",val))
    # 上のループは len,buf,key,SENT の順にpush → [esp]=SENT
    uc.reg_write(UC_X86_REG_ESP,esp)
    uc.reg_write(UC_X86_REG_EBP,0x2f8000)
    stopped=[False]
    def hook(u,addr,size,ud):
        if addr==SENT: u.emu_stop(); stopped[0]=True
    uc.hook_add(UC_HOOK_CODE,hook,begin=SENT,end=SENT)
    try:
        uc.emu_start(DEC,SENT,count=20000000)
    except UcError as e:
        return None, f"UcError {e} eip={uc.reg_read(UC_X86_REG_EIP):#x}"
    return uc.mem_read(BUF,len(data)), ("ok" if stopped[0] else "no-return")
if __name__=="__main__":
    sb1=open("SD_VIDEO/PRG011/MOV001.sb1","rb").read()
    enc=sb1[0xA0:0xA0+256]
    out,st=decrypt(b'\0'*8, enc)
    print("status:",st)
    if out: print("zero-key out[:32]:",bytes(out[:32]).hex(' '))
