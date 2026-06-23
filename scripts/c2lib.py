# 展開済みモジュールイメージ Dump_36000000_0003C000.bin から C2 をクリーンにエミュレート。
# これを「正解C2」の基準にする。decrypt(key8,data)/keysched(key8)->roundkeys を提供。
import os, struct
from unicorn import *
from unicorn.x86_const import *

ROOT=os.path.join(os.path.dirname(__file__),"..")
IMG=open(os.path.join(ROOT,"Dump_36000000_0003C000.bin"),"rb").read()
MODBASE=0x36000000
DEC=0x36012cec
KSCHED=0x360137b2
SENT=0x3f000000
STACK=0x20000000

def _mk():
    uc=Uc(UC_ARCH_X86,UC_MODE_32)
    uc.mem_map(MODBASE, (len(IMG)+0xfff)&~0xfff)
    uc.mem_write(MODBASE, IMG)
    uc.mem_map(STACK, 0x100000)          # stack
    uc.mem_map(0x10000000, 0x100000)     # key/buf/roundkeys
    uc.mem_map(SENT&~0xfff, 0x1000)      # return sentinel
    return uc

def _run(uc, eip, args):
    esp=STACK+0x80000
    for v in reversed(args):
        esp-=4; uc.mem_write(esp, struct.pack("<I",v))
    esp-=4; uc.mem_write(esp, struct.pack("<I",SENT))  # return addr
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, STACK+0x90000)
    done=[False]
    def hk(u,a,s,d):
        if a==SENT: u.emu_stop(); done[0]=True
    h=uc.hook_add(UC_HOOK_CODE, hk, begin=SENT, end=SENT)
    try:
        uc.emu_start(eip, SENT, count=5000000)
    except UcError as e:
        return False, f"{e} eip={uc.reg_read(UC_X86_REG_EIP):#x}"
    return done[0], "ok"

KEY=0x10000000; BUF=0x10010000; RK=0x10020000

def decrypt(key8, data):
    uc=_mk()
    uc.mem_write(KEY, key8.ljust(8,b'\0')[:8])
    uc.mem_write(BUF, data)
    ok,st=_run(uc, DEC, [KEY, BUF, len(data)])   # decrypt(key,buf,len)
    return bytes(uc.mem_read(BUF, len(data))), st

def keysched(key8):
    uc=_mk()
    uc.mem_write(KEY, key8.ljust(8,b'\0')[:8])
    ok,st=_run(uc, KSCHED, [KEY, RK])            # keysched(key,&rk)  ※引数順は要検証
    return bytes(uc.mem_read(RK, 64)), st

if __name__=="__main__":
    sb1=open(os.path.join(ROOT,"SD_VIDEO","PRG011","MOV001.sb1"),"rb").read()
    enc=sb1[0xA0:0xA0+32]
    out,st=decrypt(b'\0'*8, enc)
    print("decrypt status:",st)
    print("zero-key out:", out.hex(' '))
    print("expect(prev):","d1 04 2b 75 f1 c0 5b 1e 5b d8 76 34 3f 15 ad 62 1b d5 09 84 95 a8 42 ad 4b f3 5e 6f ae 1b 1d 5d")
    rk,st2=keysched(b'\0'*8)
    print("keysched status:",st2)
    print("zero-key roundkeys:", rk.hex(' '))
