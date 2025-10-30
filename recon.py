#!/usr/bin/env python3
import argparse, subprocess, os, sys, shutil
from pathlib import Path

HERE = Path(__file__).parent

def run(cmd, capture=False):
    print(f"[RUN] {' '.join(cmd)}")
    if capture:
        return subprocess.run(cmd, capture_output=True, text=True)
    else:
        return subprocess.run(cmd)

def ensure_outdir(target):
    out = HERE / "output" / target
    out.mkdir(parents=True, exist_ok=True)
    return out

def crtsh_enum(target, outpath):
    # simple wrapper
    print("[*] crt.sh enumeration (python tool)")
    r = run([sys.executable, str(HERE / "tools" / "crtsh_enum.py"), target], capture=True)
    if r and r.stdout:
        outpath.write_text(r.stdout)
    print(f"[*] wrote {outpath}")

def run_subfinder(target, outpath):
    if shutil.which("subfinder"):
        run(["subfinder", "-d", target, "-o", str(outpath)])
    else:
        print("[!] subfinder not installed; skipping.")

def probe_http(out_subs, out_alive):
    if shutil.which("httpx"):
        run(["httpx", "-l", str(out_subs), "-silent", "-o", str(out_alive)])
    else:
        print("[!] httpx not installed; skipping http probe.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    args = parser.parse_args()

    outdir = ensure_outdir(args.target)
    subs = outdir / "subdomains.txt"
    crt = outdir / "subdomains_crtsh.txt"
    alive = outdir / "alive.txt"

    crtsh_enum(args.target, crt)
    run_subfinder(args.target, outdir / "subfinder.txt")

    # merge
    lines = set()
    for p in (crt, outdir / "subfinder.txt"):
        if p.exists():
            lines.update([l.strip() for l in p.read_text().splitlines() if l.strip()])
    subs.write_text("\n".join(sorted(lines)))
    print(f"[*] subdomains written to {subs}")

    probe_http(subs, alive)
    print("[*] Completed baseline recon. Next: run recon.sh for full pipeline or extend this script.")

if __name__ == "__main__":
    main()
