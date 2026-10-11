# gpg-signed-release-verify

Verify a GPG (or deterministic demo) signature before any downloaded release artifact is executed. A fail-closed gate for agents and CI pipelines. If your workflow downloads and runs binaries built by someone else, you need this check; if you only run code from your own package manager with its own verifier, you probably do not.

## Problem

Agents and automation pipelines download executables constantly — release binaries, installers, model runners. Almost nobody verifies the signature of what they just downloaded. CDN caches get poisoned, mirrors go stale or hostile, and a 302 redirect is all it takes to swap a payload. Most desktop-app repositories treat "the artifact might be tampered with in transit" as someone else's problem; a few high-traffic proxy clients treat it as a first-class threat and sign every release artifact precisely so the download chain can be closed [unverified claim about specific projects — see the source-repo link below].

The overlooked angle: signature verification is cheap, deterministic, and local. It belongs as a **fixed gate before any tool call that executes a downloaded file** — not as a manual step a human remembers to run once.

## How it works

The gate is a single decision function with pluggable engines:

1. **Policy** (JSON): a list of trusted key fingerprints plus optional file-extension allowlist.
2. **Signature** (JSON sidecar): engine tag, artifact SHA-256, key fingerprint, and a binding MAC.
3. **Engines**:
   - `demo` — a deterministic HMAC-SHA256 binding (hash of artifact + fingerprint). This is **not** a cryptographic trust anchor; it exists so the whole pipeline is testable with zero dependencies.
   - `gpg` — shells out to the installed `gpg` binary for real detached signatures. This is the production path.
4. **Decision**: `allow` only if the artifact exists, the extension is allowed, the fingerprint is trusted, and the signature verifies. **An empty trust list denies everything (fail-closed).**

Quickstart (~5 min total):

```bash
# 1. Self-test, no dependencies (~15 s)
python self_test.py

# 2. Minimal end-to-end demo (~10 s)
echo "payload" > app.bin
python verify_gate.py sign --artifact app.bin \
    --fingerprint ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234 --out app.sig.json
echo '{"trusted_fingerprints":["ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"]}' > policy.json
python verify_gate.py check --artifact app.bin --sig app.sig.json --policy policy.json
# -> decision: allow

# 3. Full path: gpg engine (~20 s once gpg is installed)
python verify_gate.py check --artifact x.zip --sig x.zip.sig --policy policy.json --engine gpg
```

## Why not X

| Alternative | Why not |
|---|---|
| Bare `sha256sum` check | Only detects accidental corruption; the expected hash usually travels on the same compromised channel as the binary. A key-based signature does not. |
| Trust-on-first-use (TOFU) pinning | First download establishes trust; a compromised first fetch is silently locked in. Explicit policy fingerprints are reviewed, not inherited. |
| Container/image scanning | Scans for known CVEs, not for "is this the file the maintainer signed". Complementary, not a substitute. |
| In-house hash manifest on a second CDN | Extra infrastructure and another trust root to secure; GPG already gives you distributed, human-auditable key trust. |

## Minimal Fallback

No `gpg` installed? No policy file? The tool still works:

- `python verify_gate.py hash <file>` prints the SHA-256 so you can compare against a hash you obtained out-of-band (e.g. typed from the maintainer's release page).
- `--engine demo` runs the full gate flow without GPG — usable for pipeline rehearsals, never for real trust decisions.

## Design Trade-offs

Priorities: **safety > correctness > simplicity > performance.**

- Fail-closed on everything: empty trust list, unreadable policy, unknown engine → deny. Annoying but the only safe default.
- The demo engine is deliberately *not* secure; it optimizes testability. All production claims apply to the `gpg` engine only.
- Subprocess call to `gpg` with a 60 s timeout and no shell — slightly slower than a native library, but avoids adding any dependency.

## Limits & Second-order Effects

- Verifies the download chain only. A backdoored binary signed by a compromised maintainer key still verifies. Key rotation and revocation are *your* process.
- Widespread adoption side effect: teams may start treating "signature valid" as "artifact safe", skipping behavioral review of first-time artifacts. Signature is one gate, not a verdict.
- The policy file becomes a high-value target; if an agent can edit it, the gate is theater. Keep it read-only for the agent.

## FAQ

**Does the demo signature provide real security?**
No. It is an HMAC keyed by the fingerprint string, for tests and pipeline rehearsals only. Real trust requires GPG signatures from reviewed keys.

**When should you NOT use this tool?**
When the artifact comes from an OS package manager (apt/dnf/winget) that already verifies its own signatures — you would just be duplicating a stronger chain. Also skip it for pure data files you never execute.

**Why JSON sidecars instead of armored `.asc`?**
For the demo engine, JSON keeps the test path self-contained. The `gpg` engine accepts standard `.sig`/`.asc` files.

**Does it work offline?**
Yes. Both engines are fully local; no network calls anywhere in the code.

## Core Assumptions

1. The caller can obtain at least one fingerprint through a channel independent of the download itself.
2. Executing an unsigned/unverified artifact is treated as an unacceptable risk, so deny-by-default is acceptable UX.
3. `gpg` binary, when present, behaves per standard CLI semantics (`--verify` exit code 0 = valid).
4. Artifact files fit on local disk; streaming hash reads in 1 MiB blocks (measured in self-test: 5 MiB artifact verifies in well under a second on commodity hardware; run `python self_test.py` to reproduce on your machine).

## Source & Credits

Inspired by the release-signing practices of high-traffic cross-platform proxy clients (structural restatement, no text copied): https://github.com/2dust/v2rayN

---

Confidence: **High** that signature gating belongs before execution of third-party binaries (standard supply-chain practice). Confidence: **Medium** that the demo engine reduces integration friction enough to raise adoption of the real `gpg` path (based on this repo's own test coverage, not external usage data).

Time-sensitive notes (key sizes, GPG CLI flags, extension lists): **as of 2026-10-11**.

License: MIT. Contact: hcac4735@agent.qq.com
