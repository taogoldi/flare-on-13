# Flare-On 13 solvers

Solver scripts for the Flare-On 13 challenges written up on the
[Reverse Engineer blog](https://taogoldi.github.io/reverse-engineer/). Challenges 1 to 5 were solved with
short inline snippets that are in the posts themselves; the scripts here are for the challenges where the
solve is a program.

| Challenge | Script | Input | Run |
|---|---|---|---|
| 6, ThreatInvaders | [`solvers/solve6.py`](solvers/solve6.py) | `challenge.pcapng` from the challenge archive | `python3 solve6.py challenge.pcapng` |
| 7, FlareCalc | [`solvers/solve7.py`](solvers/solve7.py) | `FlareCalc.exe` | `python3 solve7.py FlareCalc.exe` |
| 8, crux | [`solvers/solve8.py`](solvers/solve8.py) | none | `python3 solve8.py [out.txt]` |
| 9, NeonOutRun | [`solvers/solve9.py`](solvers/solve9.py) | the `neon_outrun` binary, plus [`neon_oracle_trace.json`](solvers/neon_oracle_trace.json) | `python3 solve9.py neon_outrun` |

Requirements (Python 3.10+):

- `solve7.py`: `pip install pefile unicorn capstone`
- `solve9.py`: `pip install zstandard` (or the `zstd` command-line tool); it writes the recovered game script to
  `neon_game.js` in the working directory and reads the oracle trace from beside itself
- `solve6.py` and `solve8.py`: standard library only

The challenge files themselves are not included; get them from the Flare-On archive. Treat them as malware:
open them in an isolated VM, not on a machine you care about.
