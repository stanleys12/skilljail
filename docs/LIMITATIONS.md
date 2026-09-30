# Limitations & honest caveats

SkillJail is a research prototype. Where it is weak, it is weak on purpose or by current
scope — stated plainly so results aren't oversold.

### Enforcement
- **Two planes, one boundary.** Only the *kernel plane* (Bash commands and their subprocesses,
  under Seatbelt/bwrap) is true containment. The *harness plane* (Read/Write/Edit/WebFetch,
  which run inside the Claude Code process) is enforced with PreToolUse hooks — policy that a
  compromised harness could bypass. We never call the harness plane containment.
- **macOS-first.** The Seatbelt backend is implemented and tested (macOS 26.6). The bubblewrap
  backend generates args and is unit-tested but not integration-tested here, and it currently
  supports *no network* rather than an egress allowlist (the proxy needs a Unix-socket bridge
  on Linux, as `srt` does — not yet built).
- **`sandbox-exec` is deprecated** by Apple (still shipped; still used by `srt`, Codex CLI,
  Chrome). A future macOS could remove it; the Landlock path is the long-term home.
- **No syscall audit mode on macOS.** Seatbelt's `(trace)` / `(with report)` are non-functional
  on current macOS, so "what was denied" telemetry is scraped from the unified log
  (`log stream`), which is system-wide and best-effort — good for audit, not for enforcement
  (enforcement already happened in the kernel).
- **No resource quotas** (CPU/RAM/PID) in the Seatbelt backend, so B8 resource-abuse is only
  partially addressed.

### Inference
- Static and deterministic (no LLM, on purpose — an LLM inferer is an injection target). It
  will therefore **miss dynamically-constructed** targets (`curl "$HOST"` where `$HOST` comes
  from a fetched file) and **over-collect** from ambiguous prose. It is a drafting aid whose
  output a human reviews; it is not an oracle. Measured precision/recall are in EVAL.md.
- Inferring a manifest **from a malicious skill** legitimizes that skill's own bad hosts/reads
  (they're in the code). This is shown quantitatively in EVAL.md (E2b) as a negative result:
  containment comes from a manifest written for the skill's *declared purpose* (E2a), or from
  composition rules, or from a reviewer rejecting a flagged manifest — not from inference alone.

### Composition
- The cross-skill ledger reasons about declared read-classes and egress hosts. It cannot see
  data an agent carries in natural language between skills without any tool call (pure
  context-to-context leakage) — that is the same channel FIDES-style IFC targets and is future
  work.

### Evaluation
- The "gullible executor" is an upper bound on agent compliance (a real agent sometimes
  refuses), so containment numbers are conservative in the right direction.
- IOCs are measured on two robust channels — **network egress** and **persistence writes**.
  Credential-theft/RCE are measured via their egress step. Agent-control (B10–B15) and pure
  compute (B8) are out of scope for the containment metric and reported separately (flagging
  only). Raw-socket-only attacks are counted only when denial telemetry is on.
- Runs use a canary fake `$HOME` and a non-dialing proxy, so nothing a skill under test emits
  ever reaches the real network — but that also means we measure *attempts and blocks*, not
  real-world end-to-end exfiltration.

### Not a silver bullet
Pair SkillJail with a scanner (for agent-control attacks it doesn't cover) and with human
review (for permission-reuse within declared scope). It removes the largest, most mechanical
class of skill compromise; it does not remove all of it.
