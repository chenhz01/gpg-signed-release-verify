#!/usr/bin/env python3
"""Self-test for gpg-signed-release-verify.

Three required test families (ALIGNMENT rule 97):
  1. functional      - sign/verify roundtrip, policy allow
  2. error paths     - missing files, unknown key, tampered artifact
  3. extreme edges   - empty input, 5 MiB input, corrupted signature JSON

Run:  python self_test.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_gate as vg  # noqa: E402

FP = "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"
results = []


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))


def make_policy(tmp, fps=(FP,)):
    p = os.path.join(tmp, "policy.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"trusted_fingerprints": list(fps),
                   "allowed_extensions": [".bin", ".zip"]}, fh)
    return p


# ------------------------------------------------------------- functional ---
def test_functional(tmp):
    art = os.path.join(tmp, "app.bin")
    with open(art, "wb") as fh:
        fh.write(b"release payload v1")
    sig = vg.demo_sign(art, FP)
    sig_path = os.path.join(tmp, "app.sig.json")
    with open(sig_path, "w", encoding="utf-8") as fh:
        json.dump(sig, fh)
    policy = vg.load_policy(make_policy(tmp))

    r = vg.check(art, sig, policy)
    record("functional: sign+verify roundtrip allows", r["decision"] == "allow", str(r))

    r = vg.check(art, sig, vg.load_policy(make_policy(tmp, ())))
    record("functional: empty trust list denies (fail-closed)",
           r["decision"] == "deny")

    loaded = vg.load_sig_file(sig_path)
    record("functional: sig file roundtrip", loaded["artifact_sha256"] == sig["artifact_sha256"])


# ----------------------------------------------------------- error paths ---
def test_errors(tmp):
    art = os.path.join(tmp, "app.bin")
    with open(art, "wb") as fh:
        fh.write(b"payload")
    sig = vg.demo_sign(art, FP)
    policy = vg.load_policy(make_policy(tmp))

    r = vg.check(os.path.join(tmp, "nope.bin"), sig, policy)
    record("error: missing artifact denied", r["decision"] == "deny")

    r = vg.check(art, {}, policy)
    record("error: empty signature denied", r["decision"] == "deny")

    tampered = dict(sig, mac="0" * 64)
    r = vg.check(art, tampered, policy)
    record("error: forged mac denied", r["decision"] == "deny")

    with open(art, "ab") as fh:
        fh.write(b"\x00tamper")
    r = vg.check(art, sig, policy)
    record("error: tampered artifact denied", r["decision"] == "deny")
    with open(art, "wb") as fh:  # restore for later tests
        fh.write(b"payload")

    other = vg.demo_sign(art, "EEEE" * 10)
    r = vg.check(art, other, policy)
    record("error: unknown key denied", r["decision"] == "deny")

    try:
        vg.load_policy(os.path.join(tmp, "missing.json"))
        record("error: missing policy raises GateError", False)
    except vg.GateError:
        record("error: missing policy raises GateError", True)


# ------------------------------------------------------------ edge cases ---
def test_edges(tmp):
    policy = vg.load_policy(make_policy(tmp))

    empty = os.path.join(tmp, "empty.bin")
    open(empty, "wb").close()
    sig = vg.demo_sign(empty, FP)
    r = vg.check(empty, sig, policy)
    record("edge: empty artifact roundtrip", r["decision"] == "allow")

    big = os.path.join(tmp, "big.bin")
    with open(big, "wb") as fh:
        fh.write(os.urandom(5 * 1024 * 1024))
    sig_b = vg.demo_sign(big, FP)
    r = vg.check(big, sig_b, policy)
    record("edge: 5 MiB artifact roundtrip", r["decision"] == "allow")

    bad = os.path.join(tmp, "bad.sig.json")
    with open(bad, "w", encoding="utf-8") as fh:
        fh.write('{"engine": "demo", "mac": "trunc')
    try:
        vg.load_sig_file(bad)
        record("edge: corrupted sig JSON raises GateError", False)
    except vg.GateError:
        record("edge: corrupted sig JSON raises GateError", True)

    try:
        vg.demo_sign(empty, "")
        record("edge: empty fingerprint rejected", False)
    except vg.GateError:
        record("edge: empty fingerprint rejected", True)

    r = vg.check(empty, sig, policy, engine="gpg")
    record("edge: gpg engine without binary denied gracefully",
           r["decision"] == "deny" and "gpg" in r["reasons"][0])


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        test_functional(tmp)
        test_errors(tmp)
        test_edges(tmp)
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
