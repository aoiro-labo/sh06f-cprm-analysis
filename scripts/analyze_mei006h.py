import sys, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

d = open('C:/Windows/SysWOW64/mei006h.exe', 'rb').read()
print(f'Size: {len(d)} bytes')
print(f'Magic: {d[:4].hex()}')

strings = re.findall(b'[\x20-\x7e]{5,}', d)
print(f'\n=== Strings ({len(strings)}) ===')
for s in strings:
    try:
        print('  ' + s.decode('ascii'))
    except Exception:
        pass

# PE imports
print('\n=== PE Import check ===')
if d[0:2] == b'MZ':
    pe_offset = struct.unpack_from('<I', d, 0x3C)[0]
    print(f'PE offset: 0x{pe_offset:x}')
    import struct
    sig = d[pe_offset:pe_offset+4]
    print(f'PE sig: {sig}')
    machine = struct.unpack_from('<H', d, pe_offset+4)[0]
    print(f'Machine: 0x{machine:x} (0x14C=x86, 0x8664=x64)')
