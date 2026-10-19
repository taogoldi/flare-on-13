#!/usr/bin/env python3
"""Flare-On 13 #7 FlareCalc - recover the flag from FlareCalc.exe alone.

Needs: pefile, capstone, unicorn  (pip install pefile capstone unicorn)
Usage:  python3 solve7.py [path/to/FlareCalc.exe]
"""
import sys, struct, collections
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError, UC_HOOK_CODE, UC_HOOK_INSN
from unicorn.x86_const import *

M32 = 0xFFFFFFFF
LCG_A, LCG_C = 1103515245, 12345
DEJUNK_SEED = 0x429057CE          # brute-forced once; identical for every record
FSM_START, FSM_END = 52090, 4485
CIPHERTEXT_ID = 9990

# ---------------------------------------------------------------- container
def tlv(b, off):
    t = b[off]; p = off + 1; l = b[p]; p += 1
    if l & 0x80:
        n = l & 0x7F; l = int.from_bytes(b[p:p+n], 'big'); p += n
    return t, l, p

def records(path):
    pe = pefile.PE(path, fast_load=True)
    sd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]          # certificate table
    blob = open(path, 'rb').read()[sd.VirtualAddress + 8: sd.VirtualAddress + sd.Size]
    # PKCS#7 -> 3rd certificate -> extension 1.3.6.1.4.1.1337.1
    i = blob.find(bytes.fromhex('2b060104018a390104'))
    assert i > 0, 'private OID 1.3.6.1.4.1.1337.1 not found'
    _, l, p = tlv(blob, i + 8)                          # the OCTET STRING
    payload = blob[p:p+l]
    _, l, p = tlv(payload, 0)
    end, off, out = p + l, p, {}
    while off < end:
        _, l2, p2 = tlv(payload, off)
        ta, la, pa = tlv(payload, p2)
        num = int.from_bytes(payload[pa:pa+la], 'big')
        tb, lb, pb = tlv(payload, pa + la)
        out[num] = payload[pb:pb+lb]
        off = p2 + l2
    return out

# ---------------------------------------------------------------- unpacking
CYC = []; _s = 0
for _ in range(256):
    CYC.append(_s); _s = (0x6D * _s + 0x39) & 0xFF     # low byte of the LCG
INV = {v: i for i, v in enumerate(CYC)}

_T = [DEJUNK_SEED]
for _ in range(70000):
    _T.append((_T[-1] * LCG_A + LCG_C) & M32)
REAL, _p = [], 0
while _p < 69000:
    REAL.append(_p); _p += 1 + (_T[_p + 1] % 3) + 1    # 1..3 junk bytes follow each real byte
REALSET = set(REAL)

def unpack(blob):
    """strip the interleaved junk and the per-record LCG xor"""
    L = len(blob)
    votes = collections.Counter()
    for q in range(L):
        if q in REALSET: continue
        ks = blob[q] ^ (_T[q + 1] & 0xFF)              # junk byte is the LCG low byte
        if ks in INV: votes[(INV[ks] - q) % 256] += 1
    a = votes.most_common(1)[0][0]
    return bytes(blob[q] ^ CYC[(a + q) % 256] for q in REAL if q < L)

# ---------------------------------------------------------------- emulation
md = Cs(CS_ARCH_X86, CS_MODE_64)
def delay_loop(code):
    ins = list(md.disasm(code, 0)); idx = {x.address: k for k, x in enumerate(ins)}
    for k, x in enumerate(ins):
        if x.mnemonic in ('jb', 'jne', 'jl') and x.op_str.startswith('0x'):
            t = int(x.op_str, 16)
            if t < x.address and x.address - t < 64 and t in idx:
                A = B = None
                for y in ins[idx[t]:k+1]:
                    o = y.op_str
                    if y.mnemonic == 'mov' and o.startswith('dword ptr [rsp + '):
                        if o.endswith(', ecx'): B = int(o.split('+ ')[1].split(']')[0], 16)
                        if o.endswith(', eax'): A = int(o.split('+ ')[1].split(']')[0], 16)
                if A is not None and B is not None:
                    return t, x.address + x.size, A, B
    return None

CODE, STACK, STATE = 0x400000, 0x200000, 0x300000
def run(code, c, state):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x10000); uc.mem_map(STACK - 0x100000, 0x200000); uc.mem_map(STATE, 0x1000)
    uc.mem_write(CODE, code); uc.mem_write(STATE, bytes(state))
    ret = CODE + 0x8000; uc.mem_write(ret, b'\xf4')
    uc.reg_write(UC_X86_REG_RSP, STACK); uc.mem_write(STACK, struct.pack('<Q', ret))
    uc.reg_write(UC_X86_REG_RCX, c); uc.reg_write(UC_X86_REG_RDX, STATE)
    uc.reg_write(UC_X86_REG_R8, 0); uc.reg_write(UC_X86_REG_R9, 0)
    def cpuid(u, _):
        if u.reg_read(UC_X86_REG_EAX) == 1:
            u.reg_write(UC_X86_REG_EAX, 0x000306A9); u.reg_write(UC_X86_REG_EBX, 0x00100800)
            u.reg_write(UC_X86_REG_ECX, 0x7FFAFBBF); u.reg_write(UC_X86_REG_EDX, 0xBFEBFBFF)
        return True
    uc.hook_add(UC_HOOK_INSN, cpuid, None, 1, 0, UC_X86_INS_CPUID)
    d = delay_loop(code)
    if d:                                              # skip the 1,000,000-iteration stall
        head, after, A, B = d; done = [False]
        def hook(u, addr, size, _):
            if not done[0]:
                done[0] = True
                sp = u.reg_read(UC_X86_REG_RSP)
                u.mem_write(sp + A, struct.pack('<I', 0xF4240))
                u.mem_write(sp + B, struct.pack('<I', 0x6A4AE6E0))
                u.reg_write(UC_X86_REG_RIP, CODE + after)
        uc.hook_add(UC_HOOK_CODE, hook, begin=CODE + head, end=CODE + head)
    try:
        uc.emu_start(CODE, ret, count=3000000)
    except UcError:
        return None, None
    return uc.reg_read(UC_X86_REG_EAX) & M32, bytes(uc.mem_read(STATE, 32))

# ---------------------------------------------------------------- XTEA
def xtea_decrypt(ct, key):
    out = b''
    for i in range(0, len(ct), 8):
        v0, v1 = struct.unpack('>2I', ct[i:i+8])
        s = (0x9E3779B9 * 32) & M32
        for _ in range(32):
            v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + key[(s >> 11) & 3]))) & M32
            s = (s - 0x9E3779B9) & M32
            v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + key[s & 3]))) & M32
        out += struct.pack('>2I', v0, v1)
    return out

def main(path='FlareCalc.exe'):
    recs = records(path)
    print(f'[+] {len(recs)} records in the fake Authenticode blob')
    funcs = {i: unpack(b) for i, b in recs.items() if i != 3821}
    ct = funcs.pop(CIPHERTEXT_ID)
    print(f'[+] ciphertext record {CIPHERTEXT_ID}: {len(ct)} bytes')

    seen, found = set(), []
    def dfs(fid, st, path):
        if fid == FSM_END:
            found.append((bytes(path), st)); return True
        if (fid, st) in seen or len(path) > 100: return False
        seen.add((fid, st))
        nxt = []
        for c in range(256):
            r, ns = run(funcs[fid], c, st)
            if r in funcs or r == FSM_END: nxt.append((c, r, ns))
        nxt.sort(key=lambda t: (not (32 <= t[0] < 127), t[0]))
        for c, r, ns in nxt:
            path.append(c)
            if dfs(r, ns, path): return True
            path.pop()
        return False
    dfs(FSM_START, bytes(32), [])
    key_in, state = found[0]
    print(f'[+] state-machine input: {key_in.decode()}')
    print(f'[+] final 32-byte state: {state.hex()}')
    S = struct.unpack('<8I', state)
    flag = xtea_decrypt(ct, [S[i + 4] ^ S[i] for i in range(4)])
    print(f'[+] FLAG: {flag.decode()}')

if __name__ == '__main__':
    main(*sys.argv[1:])
