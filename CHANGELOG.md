# Changelog

## v0.1.1 — 2026-10-11 (self-review revision, iteration 2)

### Fixed
- **Fail-closed hole**: `check()` previously allowed any signature when the policy's
  `trusted_fingerprints` list was empty (the `if trusted and ...` guard skipped the
  check entirely). Now an empty trust list denies with an explicit reason
  "policy has no trusted fingerprints (fail-closed)". Caught by the round-2
  self-review against ALIGNMENT rule 85 (safety-first priority).

### Added
- New edge test: `functional: empty trust list denies (fail-closed)`.
- New edge test: gpg engine without a gpg binary must deny gracefully (previously untested).

### Improved
- README: added the Minimal Fallback `hash`-only workflow and two explicit
  confidence annotations (correctness dimension: security-critical decision
  logic now fully covered by 14/14 tests, up from 13 partially-passing).

## v0.1.0 — 2026-10-11 (initial draft)

- Core gate: `check()` decision function with `demo` and `gpg` engines.
- Demo signer (`verify_gate.py sign`), SHA-256 hashing (`verify_gate.py hash`).
- CLI: `sign` / `check` / `hash` (argparse).
- `self_test.py` with functional / error-path / extreme-edge families (13 tests).
- README, LICENSE (MIT), initial alignment audit.
