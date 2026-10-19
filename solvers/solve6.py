#!/usr/bin/env python3
"""Flare-On 13 #6 ThreatInvaders - recover the flag from challenge.pcapng alone."""
import struct, collections, re, json, base64, uuid, sys

M64 = (1 << 64) - 1

def packets(path):
    d = open(path, 'rb').read(); off = 0
    while off + 8 <= len(d):
        t, l = struct.unpack_from('<II', d, off)
        if l < 12 or off + l > len(d): break
        if t == 6:
            _, _, _, cap, _ = struct.unpack_from('<IIIII', d, off + 8)
            yield d[off + 28: off + 28 + cap]
        off += l

def streams(path):
    segs = collections.defaultdict(dict)
    for p in packets(path):
        if len(p) < 34 or struct.unpack_from('>H', p, 12)[0] != 0x0800: continue
        if p[23] != 6: continue
        ihl = (p[14] & 0xf) * 4; t = 14 + ihl
        sport, dport = struct.unpack_from('>HH', p, t)
        seq = struct.unpack_from('>I', p, t + 4)[0]
        doff = (p[t + 12] >> 4) * 4
        total = struct.unpack_from('>H', p, 16)[0]
        # TSO frames under-report IP total length; trust the frame when it is longer
        end = 14 + total if (len(p) - 14 - total) <= 6 else len(p)
        pay = p[t + doff:end]
        if pay: segs[(sport, dport)][seq] = pay
    return {k: b''.join(v[s] for s in sorted(v)) for k, v in segs.items()}

def http_requests(blob):
    out = []; p = 0
    while p < len(blob):
        h = blob.find(b'\r\n\r\n', p)
        if h < 0: break
        head = blob[p:h].decode('latin1'); p = h + 4
        m = re.search(r'Content-Length: (\d+)', head)
        n = int(m.group(1)) if m else 0
        out.append((head.split('\r\n')[0], blob[p:p + n])); p += n
    return out

def http_responses(blob):
    out = []
    idx = [m.start() for m in re.finditer(rb'HTTP/1\.1 \d\d\d', blob)] + [len(blob)]
    for a, b in zip(idx, idx[1:]):
        blk = blob[a:b]; h = blk.find(b'\r\n\r\n')
        out.append(blk[h + 4:])
    return out

def fmix64(x):
    x &= M64
    x ^= x >> 33; x = (x * 0xff51afd7ed558ccd) & M64
    x ^= x >> 29; x = (x * 0xc4ceb9fe1a85ec53) & M64
    return (x ^ (x >> 32)) & M64

class Keystream:
    """Implant cipher: LCG seeded from the MachineGuid, output = top byte of state."""
    def __init__(self, guid16):
        a = int.from_bytes(guid16[:8], 'little')
        b = int.from_bytes(guid16[8:], 'little')
        h = (((a >> 2) + 0x9e3779b97f4a7c15 + ((a << 6) & M64) + b) & M64) ^ a
        self.st = fmix64(h)
    def xor(self, data):
        out = bytearray()
        for c in data:
            self.st = (self.st * 0x5851f42d4c957f2d + 0x14057b7ef767814f) & M64
            out.append(c ^ (self.st >> 56))
        return bytes(out)

def main(path='challenge.pcapng'):
    st = streams(path)
    c2s = next(v for k, v in st.items() if k[1] == 80)
    s2c = next(v for k, v in st.items() if k[0] == 80)

    tele = [json.loads(b) for l, b in http_requests(c2s) if 'telemetry' in l]
    # board responses that carry an injected entry: first4(name) ^ score == "cmd:"
    cmds = []
    for body in http_responses(s2c):
        if b'"player_name"' not in body: continue
        for e in json.loads(body).get('entries', []):
            nm = e['player_name'].encode()[:4].ljust(4, b'\0')
            if bytes(x ^ y for x, y in zip(nm, struct.pack('<I', e['score']))) == b'cmd:':
                cmds.append(base64.b64decode(e['comment_b64']))
    cmds = list(dict.fromkeys(cmds))

    # telemetry whose reported length is 0x2010 leaks MachineGuid ^ reversed(SessionId)
    leak = next(t for t in tele if t['feedback_length'] == 0x2010)
    exfil = base64.b64decode(leak['feedback_b64'])[:16]
    sid = uuid.UUID(leak['session_id']).bytes_le
    guid = bytes(a ^ b for a, b in zip(exfil, sid[::-1]))
    print('MachineGuid :', uuid.UUID(bytes_le=guid))

    # command output exfils carry length | 0x4000
    outs = [base64.b64decode(t['feedback_b64'])[:t['feedback_length'] & 0x3fff]
            for t in tele if t['feedback_length'] & 0x4000]

    ks = Keystream(guid)
    for i, (cmd, out) in enumerate(zip(cmds, outs), 1):
        print(f'\n--- command {i}: {ks.xor(cmd).decode()}')
        print(ks.xor(out).decode('utf-8', 'replace').rstrip())

if __name__ == '__main__':
    main(*sys.argv[1:])
