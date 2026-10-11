# Alignment Audit (Rules 85-100 / 16 items)

Repo: gpg-signed-release-verify — audited 2026-10-11 (post v0.1.1 revision)

| # | Check | Status | Evidence |
|---|-------|--------|----------|
| 1 | Safety/Ethics section (security-domain repo) | PASS | README "Limits & Second-order Effects" (signature≠safety, policy-file threat model); demo engine explicitly marked non-security |
| 2 | Privacy/redaction: zero keys/tokens/real names | PASS | `grep -rnE "(sk-\|ghp_\|api[_-]?key)" .` → 0 hits; only contact hcac4735@agent.qq.com; example fingerprint is a synthetic placeholder |
| 3 | Copyright boundary (>50-word copying) | PASS | README "Source & Credits" is link + structural restatement; no text copied from source repo; LICENSE (MIT) present |
| 4 | Fact-check labeling of numbers | PASS | README perf claim cites self-test with reproduce command `python self_test.py`; source-repo claim tagged [unverified] |
| 5 | Confidence grading (≥2 explicit) | PASS | README bottom: High + Medium annotations, each with one-line basis |
| 6 | Minimal Fallback (PLAN B) | PASS | README "Minimal Fallback" — hash-only mode and demo engine work without gpg/policy |
| 7 | Quickstart timing | PASS | README Quickstart: "~5 min total", per-step timings (15 s / 10 s / 20 s), staged minimal→full path |
| 8 | Design trade-off priority | PASS | README "Design Trade-offs": safety > correctness > simplicity > performance |
| 9 | CHANGELOG ≥2 iterations | PASS | CHANGELOG.md v0.1.0 + v0.1.1 with named improvements |
| 10 | Exemption instruction (session rule) | N/A | Session-level governance; static repo content not applicable |
| 11 | Time-sensitive data dated | PASS | README bottom: "as of 2026-10-11" for key/GPG-flag/extension claims |
| 12 | Explicit core assumptions (≥3) | PASS | README "[Core Assumptions]" lists 4 |
| 13 | Three-family self-test, all PASS | PASS | `python self_test.py` → 14/14 (functional 3, error paths 6, extreme edges 5 incl. empty input, 5 MiB input, corrupted sig JSON) |
| 14 | Socratic FAQ "When NOT to use" | PASS | README FAQ: "When should you NOT use this tool?" (package-manager case) |
| 15 | ≥2 content iterations, ≥20% one dimension | PASS | v0.1.1 fixed a fail-closed security hole + added 2 tests; decision-logic test coverage 13→14 cases and a critical correctness fix (CHANGELOG documents both) |
| 16 | ≤60-word first paragraph with judgment | PASS | README opening paragraph: 51 words, ends with a need/no-need judgment |

Additional: Second-order effects section — PASS (README "Limits & Second-order Effects": false trust in "signature valid", policy-file as new attack surface).
