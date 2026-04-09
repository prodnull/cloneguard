# Limitations

CloneGuard raises the cost of prompt injection attacks. It does not eliminate
them. This page documents known limitations.

## Detection Gaps

**Novel attacks.** Payloads that evade both regex patterns and the semantic
classifier will not be detected. The adaptive red team showed that Claude can
craft payloads that bypass detection 16.7% of the time using
bureaucratic-documentation framing.

**Short payloads in long files.** The MiniLM classifier uses mean-pooling,
which dilutes short attack payloads embedded in long code blocks. This is an
architectural limitation of the classifier.

**Subtle code modification instructions.** Instructions like "use http:// not
https://" or "remove the input validation" are difficult to distinguish from
legitimate coding guidance. These require Tier 2 (LLM-based) detection.

**Domain-specific false positives.** Security documentation, CTF writeups, and
research files that describe attack patterns will trigger detections. Use
`cloneguard allow` to allowlist reviewed files.

## Enforcement Gaps

**Not a sandbox.** CloneGuard scans and gates tool calls. It does not prevent
the agent from executing arbitrary code if a payload bypasses all detection.

**Post-approval attacks.** Once a tool call is approved, CloneGuard has no
visibility into what happens during execution. A command that passes pre-scan
but behaves differently at runtime is not caught.

**Agent runtime modification.** If an attacker can modify the agent's runtime
environment (memory, process state), CloneGuard's hook-level position does not
help.

## Scope Limitations

**Not a code scanner.** CloneGuard catches prompt injection, not traditional
vulnerabilities (XSS, SQLi, logic bugs, insecure dependencies).

**Single-agent focus.** The behavioral sequence monitor tracks one agent session.
Cross-agent coordination attacks (agent A exfiltrates via agent B) are not
detected.

**Trajectory data coverage.** False positive rates are validated against
coding-agent sessions (SWE-bench). Browser, financial, autonomous, and CI/CD
agent domains do not yet have trajectory data for calibration. Detection rules
for these domains should be treated as experimental.

## Not a Silver Bullet

CloneGuard is defense in depth. Use alongside:

- Restricted agent permissions (principle of least privilege)
- Network isolation for agent sessions
- Read-only containers for untrusted repositories
- Code review for security-sensitive changes
- Agent permission models (Claude Code's permission system, Cursor's
  `failClosed` hooks)

No guarantee of long-term durability. Advances in adversarial ML or novel
exploitation techniques could render any detection approach less effective.
This is published as a practical improvement over no defense, not a solved
problem.
