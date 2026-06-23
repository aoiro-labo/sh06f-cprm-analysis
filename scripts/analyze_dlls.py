import sys, re, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def analyze(path):
    d = open(path, 'rb').read()
    print(f'\n=== {path} ({len(d)} bytes) ===')
    # ASCII文字列
    strings = re.findall(b'[\x20-\x7e]{6,}', d)
    for s in strings:
        try:
            t = s.decode('ascii')
            # 意味ありそうなものだけ表示
            if any(kw in t.lower() for kw in ['pipe', 'dll', 'key', 'title', 'media', 'cprm',
                                               'etk', 'kmu', 'mei', 'sdb', 'sdpa', 'c2',
                                               'alter', 'protect', 'secret', 'encrypt', 'decrypt',
                                               'sb1', 'mpeg', 'ats', 'lock', 'auth', 'challenge',
                                               'response', 'secure', 'device', 'read', 'write']):
                print(f'  {t}')
        except Exception:
            pass
    # Wide (UTF-16LE) 文字列
    wide_strings = re.findall(b'(?:[\x20-\x7e]\x00){4,}', d)
    for ws in wide_strings:
        try:
            t = ws.decode('utf-16-le').strip()
            if t and len(t) > 3:
                print(f'  [W] {t}')
        except Exception:
            pass

for path in [
    'C:/Windows/SysWOW64/sddevmgr.dll',
    'C:/Windows/SysWOW64/sda/sdpaums.dll',
    'C:/Windows/SysWOW64/sda/SDPAXIOD.DLL',
    'C:/Windows/SysWOW64/sda/SDPAXUMS.dll',
]:
    try:
        analyze(path)
    except Exception as e:
        print(f'Error: {path}: {e}')
