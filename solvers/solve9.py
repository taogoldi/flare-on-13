#!/usr/bin/env python3
"""
Flare-On 13, challenge 9, "NeonOutRun".

    python3 solve9.py /path/to/neon_outrun [neon_oracle_trace.json]

STAGE 1 (fully static): unpack the game script.

    A 21 MB stripped Linux Tauri app that also statically links a whole V8.  The
    front end is a racing game; each frame it calls the Rust command
    `plugin:neon|e`, which runs `tick()` inside the embedded V8 isolate.  That
    JavaScript is stored as a 1942-byte blob hidden in the middle of the Rust
    string pool and unpacked in four steps:

        xor 2-byte key (0xD3,0x5A) -> drop every 9th byte (0xFF stuffing)
            -> zstd -> raw DEFLATE -> 4229 bytes of JS

    The key falls out of a known plaintext: the stuffing bytes are all 0xFF, so
        key[0] = blob[0] ^ 0xFF      key[1] = blob[9] ^ 0xFF
    and that property is also the signature this script scans the file for, so
    no offset is hard-coded.

    Driving the 28 laps makes the script spell out
        decode_this_system_to_win_it@f1are-on.com
    which is a decoy: a digit 1 in place of the l, and the sentence is an
    instruction, not a flag.

STAGE 2: the system it means.

    Before running the script, the Rust side replaces three JS builtins with
    native callbacks:

        Array.prototype.sort        -> sub_67DEB2
        Math.min                    -> sub_67EB83
        String.prototype.replaceAll -> sub_67E81E

    * sort() is called once, on the array of 28 lap positions.  The hook draws a
      random scale K = 1 + 65534*rand, pushes every lap position * K into a
      global queue, and stores the *sum* of those scaled values in a global g2.

    * Math.min() is called exactly once per lap, as
      Math.min(bestLapSeconds, lapSecs).  The hook pops one queue entry q_i,
      pushes trunc(lapSecs) into a global byte vector, and accumulates

            g1 += q_i * sin( (A_i + trunc(lapSecs)) degrees )

      where A_i comes from an obfuscated table keyed by the lap index.

    * replaceAll() checks |g1| > 1e-6, |g2| > 1e-6 and |g1 - g2| < 1e-6.  When
      that holds it overwrites the string with the collected byte vector and
      adds 0x3B to byte 30, which turns the decoy's '1' back into 'l'.

    Since g2 is exactly the sum of the q_i, g1 == g2 requires sin(...) == 1 for
    every lap, i.e.

            lap_time_i = 90 - A_i

    and those 28 byte values *are* the flag.  A_i is produced by two
    control-flow-flattened functions, so this script recovers it by measurement
    instead: the supplied trace is from an instrumented run that replaced the
    packed script with a probe (same packer, re-encoded) calling
    Math.min(1e9, b) for b = 0,1,2,3 while g1 and the queue were sampled out of
    /proc/<pid>/mem.  sin((A_i + b) deg) = delta_g1 / q_i falls straight out.

    Verified end-to-end: feeding the recovered 28 bytes back through the real
    Math.min hook makes the real replaceAll hook print the flag itself.
"""

import json
import math
import os
import re
import subprocess
import sys
import tempfile
import zlib

STUFF_STRIDE = 9
STUFF_BYTE = 0xFF
MIN_MARKERS = 20

# sin((A_i + b) degrees) for b = 0, measured per lap (see module docstring)
MEASURED_SIN_B0 = [
    0.139173, 0.629320, -0.087156, -0.121869, -0.224951, 0.629320, -0.342020,
    -0.438371, -0.087156, 0.615661, -0.139173, 0.669131, -0.453990, -0.438371,
    -0.087156, -0.438371, 0.669131, -0.087156, -0.207912, 0.629320, 0.629320,
    -0.309017, -0.087156, -0.173648, 0.656059, -0.529919, -0.529919, -0.515038,
]


# ------------------------------------------------------------------ zstd glue
def zstd_decompress(data):
    try:
        import zstandard
        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    except ImportError:
        pass
    with tempfile.NamedTemporaryFile(suffix=".zst", delete=False) as fh:
        fh.write(data)
        path = fh.name
    try:
        return subprocess.run(["zstd", "-d", "-c", path],
                              check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit("need the `zstandard` python package or the `zstd` "
                         "command-line tool: %s" % exc)


# ------------------------------------------------------- stage 1: the unpacker
def find_blobs(data):
    """Runs where a fixed 2-byte XOR key turns every 9th byte into 0xFF."""
    n = len(data)
    out = []
    i = 0
    while i < n - 256:
        k0 = data[i] ^ STUFF_BYTE
        k1 = data[i + STUFF_STRIDE] ^ STUFF_BYTE
        count = 0
        j = i
        while j < n:
            key = k0 if ((j - i) // STUFF_STRIDE) % 2 == 0 else k1
            if data[j] ^ key != STUFF_BYTE:
                break
            count += 1
            j += STUFF_STRIDE
        if count >= MIN_MARKERS:
            out.append((i, count, k0, k1))
            i = j
        else:
            i += 1
    return out


def unpack(data, off, markers, k0, k1):
    length = markers * STUFF_STRIDE + STUFF_STRIDE
    blob = data[off:off + length]
    plain = bytes(b ^ (k0 if (i & 1) == 0 else k1) for i, b in enumerate(blob))
    stripped = bytes(b for i, b in enumerate(plain) if i % STUFF_STRIDE != 0)
    inner = zstd_decompress(stripped)
    return zlib.decompressobj(-15).decompress(inner), len(blob), len(inner)


def decoy_from_script(js):
    """The sentence the game prints if you simply win."""
    text = js.decode("utf-8", "replace")
    msgs = re.findall(r'"((?:[^"\\]|\\.)*)"',
                      re.search(r"const messages=\[(.*?)\];", text, re.S).group(1))
    table = [int(x) for x in re.search(r"map=\[([0-9,\s]+)\];", text).group(1).split(",")]
    suffix = re.search(r"fromCharCode\(([0-9,]+)\)", text)
    tail = "".join(chr(int(x)) for x in suffix.group(1).split(",")) if suffix else ""
    s = "".join(msgs[(lap - 1) // 2][table[lap - 1]] for lap in range(1, len(table) + 1))
    return (s + tail).replace(" ", "_")


# ------------------------------------------------- stage 2: solve the real flag
def sines_from_trace(path):
    """delta_g1 / q_i per lap, for each probe value b, from an instrumented run."""
    recs = json.load(open(path))
    rounds, cur = [], None
    for x in recs:
        if x["qlen"] == 28 and x.get("q"):
            if cur:
                rounds.append(cur)
            cur = {"q": x["q"], "g": []}
        if cur is not None:
            cur["g"].append(x["g1"])
    if cur:
        rounds.append(cur)
    out = []
    for rd in rounds:
        q, seq = rd["q"], rd["g"]
        d = [seq[i + 1] - seq[i] for i in range(len(seq) - 1)][:28]
        out.append([d[i] / q[i] for i in range(len(d))])
    return out


def solve(sin_rounds):
    """b_i = 90 - A_i, where sin((A_i + b) deg) was measured for b = 0,1,2,..."""
    base = sin_rounds[0]
    flag, rows = [], []
    for i, s in enumerate(base):
        a = round(math.degrees(math.asin(max(-1.0, min(1.0, s)))))
        ok = all(abs(math.sin(math.radians(a + b)) - sin_rounds[b][i]) < 1e-5
                 for b in range(len(sin_rounds)))
        flag.append(90 - a)
        rows.append((i, s, a, 90 - a, chr(90 - a), ok))
    return flag, rows


# ------------------------------------------------------------------------ main
def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: solve9.py /path/to/neon_outrun [trace.json]")
    data = open(sys.argv[1], "rb").read()
    print("binary: %s (%d bytes)\n" % (sys.argv[1], len(data)))

    js = None
    for off, markers, k0, k1 in find_blobs(data):
        try:
            js, blob_len, inner_len = unpack(data, off, markers, k0, k1)
        except Exception:
            continue
        if b"function" not in js or b"messages" not in js:
            js = None
            continue
        print("STAGE 1 - packed script")
        print("  blob at file offset 0x%x, %d stuffing markers, xor key %02X %02X"
              % (off, markers, k0, k1))
        print("  %d bytes -> xor/de-stuff -> %d -> zstd -> %d -> inflate -> %d"
              % (blob_len, blob_len - blob_len // STUFF_STRIDE - 1,
                 inner_len, len(js)))
        break
    if js is None:
        raise SystemExit("no packed blob found")
    with open("neon_game.js", "wb") as fh:
        fh.write(js)
    print("  script written to neon_game.js")
    print("  in-game decoy: %s\n" % decoy_from_script(js))

    trace = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "neon_oracle_trace.json")
    if os.path.exists(trace):
        rounds = sines_from_trace(trace)
        print("STAGE 2 - hook measurements from %s (%d probe rounds)"
              % (os.path.basename(trace), len(rounds)))
    else:
        rounds = [MEASURED_SIN_B0]
        print("STAGE 2 - using the measurements embedded in this script")

    flag, rows = solve(rounds)
    print("  lap   sin(b=0)      A    90-A  char  model")
    for i, s, a, b, c, ok in rows:
        print("  %3d  %9.6f  %5d  %5d   %-4r %s"
              % (i, s, a, b, c, "ok" if ok else "MISMATCH"))
    local = bytes(flag).decode()
    print()
    print("  required lap times (seconds) = the flag bytes")
    print()
    print("FLAG: %s@flare-on.com" % local)


if __name__ == "__main__":
    main()
