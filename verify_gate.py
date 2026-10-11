#!/usr/bin/env python3
"""gpg-signed-release-verify: a signature gate for downloaded release artifacts.

Pure-stdlib CLI that sits between "agent downloaded a binary" and "agent runs
it". Verification engine is pluggable:

  * ``demo``  - deterministic HMAC-based detached signature, used by self
                tests and CI so the whole flow runs with zero dependencies.
  * ``gpg``   - shells out to the ``gpg`` binary for real detached signatures
                (the production path; GPG itself is NOT bundled).

The gate never decides trust by itself: trust comes from a policy file that
lists trusted key fingerprints. Verify-then-run is the caller's contract.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile

DEMO_SIG_EXT = ".sig.json"
MAX_DEMO_ARTIFACT = 512 * 1024 * 1024  # refuse demo-signing absurd inputs


class GateError(Exception):
    """Raised for structural/usage errors (bad policy, bad signature file)."""


# ---------------------------------------------------------------- hashing ---
def sha256_file(path: str, block_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(block_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------ demo engine ---
def demo_sign(artifact_path: str, fingerprint: str) -> dict:
    """Create a deterministic demo signature (NOT a security primitive)."""
    if not fingerprint or not isinstance(fingerprint, str):
        raise GateError("fingerprint must be a non-empty string")
    size = os.path.getsize(artifact_path)
    if size > MAX_DEMO_ARTIFACT:
        raise GateError("demo signer refuses artifacts > 512 MiB")
    digest = sha256_file(artifact_path)
    mac = hmac.new(
        fingerprint.encode("utf-8"), digest.encode("ascii"), hashlib.sha256
    ).hexdigest()
    return {
        "engine": "demo",
        "artifact": os.path.basename(artifact_path),
        "artifact_sha256": digest,
        "fingerprint": fingerprint,
        "mac": mac,
    }


def demo_verify(artifact_path: str, sig: dict) -> tuple[bool, str]:
    if sig.get("engine") != "demo":
        return False, "not a demo signature"
    digest = sha256_file(artifact_path)
    if not hmac.compare_digest(digest, sig.get("artifact_sha256", "")):
        return False, "artifact hash mismatch (file changed after signing)"
    expect = hmac.new(
        sig.get("fingerprint", "").encode("utf-8"),
        digest.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expect, sig.get("mac", "")):
        return False, "mac mismatch (wrong key or forged signature)"
    return True, "demo signature valid"


# ------------------------------------------------------------- gpg engine ---
def gpg_verify(artifact_path: str, sig_path: str, gpg_bin: str = "gpg",
               keyring: str | None = None) -> tuple[bool, str]:
    """Run ``gpg --verify``; returns (ok, detail). Missing binary -> deny."""
    cmd = [gpg_bin, "--batch", "--no-tty", "--verify"]
    if keyring:
        cmd += ["--keyring", keyring]
    cmd += [sig_path, artifact_path]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60,
            shell=False, check=False,
        )
    except FileNotFoundError:
        return False, "gpg binary not found; install GPG for the production path"
    except subprocess.TimeoutExpired:
        return False, "gpg verification timed out"
    if proc.returncode == 0:
        return True, "gpg signature valid"
    return False, (proc.stderr or proc.stdout or "gpg failed").strip()[:400]


# ----------------------------------------------------------------- policy ---
def load_policy(path: str | None) -> dict:
    if path is None:
        return {"trusted_fingerprints": [], "allowed_extensions": None}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot read policy: {exc}") from exc
    if not isinstance(data.get("trusted_fingerprints"), list):
        raise GateError("policy.trusted_fingerprints must be a list")
    return data


def check(artifact_path: str, sig: dict, policy: dict,
          engine: str = "auto", gpg_bin: str = "gpg") -> dict:
    """Full gate decision. Returns {'decision': 'allow'|'deny', 'reasons': []}."""
    reasons: list[str] = []
    if not os.path.isfile(artifact_path):
        return {"decision": "deny", "reasons": ["artifact not found"]}
    if not isinstance(sig, dict) or not sig:
        return {"decision": "deny", "reasons": ["signature missing or unreadable"]}

    trusted = policy.get("trusted_fingerprints") or []
    fp = sig.get("fingerprint", "")
    if not trusted:
        reasons.append("policy has no trusted fingerprints (fail-closed)")
    elif fp not in trusted:
        reasons.append(f"fingerprint {fp!r} not in policy trust list")

    allowed_ext = policy.get("allowed_extensions")
    if allowed_ext:
        ext = os.path.splitext(artifact_path)[1].lower()
        if ext not in [e.lower() for e in allowed_ext]:
            reasons.append(f"extension {ext!r} not allowed by policy")

    engine_name = sig.get("engine", "demo") if engine == "auto" else engine
    if engine_name == "demo":
        ok, detail = demo_verify(artifact_path, sig)
    elif engine_name == "gpg":
        ok, detail = gpg_verify(artifact_path, sig_path=sig.get("_sig_path", ""),
                                gpg_bin=gpg_bin)
    else:
        ok, detail = False, f"unknown engine {engine_name!r}"
    if not ok:
        reasons.append(detail)
    return {"decision": "allow" if not reasons else "deny", "reasons": reasons}


def load_sig_file(sig_path: str) -> dict:
    try:
        with open(sig_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot read signature file: {exc}") from exc


# -------------------------------------------------------------------- CLI ---
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="verify_gate",
        description="Signature gate for downloaded release artifacts.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_sign = sub.add_parser("sign", help="create a demo signature (tests only)")
    p_sign.add_argument("--artifact", required=True)
    p_sign.add_argument("--fingerprint", required=True)
    p_sign.add_argument("--out", required=True)

    p_chk = sub.add_parser("check", help="gate decision for one artifact")
    p_chk.add_argument("--artifact", required=True)
    p_chk.add_argument("--sig", required=True)
    p_chk.add_argument("--policy", required=True)
    p_chk.add_argument("--engine", default="auto", choices=["auto", "demo", "gpg"])

    p_hash = sub.add_parser("hash", help="print sha256 of a file")
    p_hash.add_argument("file")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "sign":
            sig = demo_sign(args.artifact, args.fingerprint)
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(sig, fh, indent=2, sort_keys=True)
            print(f"wrote {args.out}")
            return 0
        if args.cmd == "check":
            sig = load_sig_file(args.sig)
            if args.engine == "gpg":
                sig["_sig_path"] = args.sig
            policy = load_policy(args.policy)
            result = check(args.artifact, sig, policy, engine=args.engine)
            print(json.dumps(result, indent=2))
            return 0 if result["decision"] == "allow" else 2
        if args.cmd == "hash":
            print(sha256_file(args.file))
            return 0
    except (GateError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
