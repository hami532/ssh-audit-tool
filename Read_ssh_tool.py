#!/usr/bin/env python3


import argparse
import re
import os
import sys
from pathlib import Path

DEFAULT_PATHS = ["/etc/ssh/sshd_config", "/etc/sshd_config"]

CHECKS = {
    "PermitRootLogin": {
        "good": ["no", "prohibit-password"],
        "warn": ["yes"]
    },
    "PasswordAuthentication": {
        "good": ["no"],
        "warn": ["yes"]
    },
    "PermitEmptyPasswords": {
        "good": ["no"],
        "warn": ["yes"]
    },
    "ChallengeResponseAuthentication": {
        "good": ["no"],
        "warn": ["yes"]
    },
    "PubkeyAuthentication": {
        "good": ["yes"],
        "warn": ["no"]
    },
    "X11Forwarding": {
        "good": ["no"],
        "warn": ["yes"]
    },
    "Protocol": {
       
        "good": ["2"],
        "warn": ["1", "1,2"]
    }
}

def parse_sshd_config(text):
    cfg = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
      
        parts = re.split(r"\s+", line, maxsplit=1)
        if len(parts) == 1:
            key, val = parts[0], ""
        else:
            key, val = parts
       
        key = key.strip()
        val = val.strip()
       
        cfg[key] = val
    return cfg

def audit_config(cfg):
    findings = []
    for key, rules in CHECKS.items():
        val = cfg.get(key)
        if val is None:
            findings.append((key, "missing", "Key not set explicitly (may be default). Check default for your distro."))
            continue
        vnorm = val.lower()
        if vnorm in rules["good"]:
            findings.append((key, "ok", f"{key} = {val}"))
        elif vnorm in rules["warn"]:
            findings.append((key, "warn", f"{key} = {val}"))
        else:
            findings.append((key, "warn", f"{key} = {val} (unknown/atypical)"))
    return findings

def find_config_path(provided):
    if provided:
        return Path(provided)
    for p in DEFAULT_PATHS:
        if Path(p).exists():
            return Path(p)
    return None

def main():
    parser = argparse.ArgumentParser(description="Simple SSHD config auditor (read-only).")
    parser.add_argument("--file", "-f", help="path to sshd_config (default: auto /etc/ssh/sshd_config)")
    args = parser.parse_args()

    path = find_config_path(args.file)
    if not path or not path.exists():
        print("Error: sshd_config file not found. Use --file to specify path.")
        sys.exit(2)

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"Unable to read {path}: {e}")
        sys.exit(3)

    cfg = parse_sshd_config(text)
    findings = audit_config(cfg)

    print(f"\nSSH Audit Report for: {path}\n" + "-"*50)
    ok_count = warn_count = missing_count = 0
    for key, status, note in findings:
        if status == "ok":
            ok_count += 1
            print(f"[OK]    {key:25} - {note}")
        elif status == "warn":
            warn_count += 1
            print(f"[WARN]  {key:25} - {note}")
        else:
            missing_count += 1
            print(f"[MISSING]{key:22} - {note}")
    print("-"*50)
    print(f"Summary: OK={ok_count}  WARN={warn_count}  MISSING={missing_count}\n")

    
    try:
        import subprocess
        p = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=3)
        if p.returncode == 0:
            print("sshd -T output (effective config):")
            # show some important effective settings
            for line in p.stdout.splitlines():
                if any(k.lower() in line for k in ["permitrootlogin", "passwordauthentication", "pubkeyauthentication", "x11forwarding"]):
                    print("  " + line)
        else:
            
            pass
    except Exception:
        pass

if __name__ == "__main__":
    main()

