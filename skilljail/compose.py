"""Composition rules: the multi-skill problem.

Kernel rules are per-process; the agent's *context* is the channel that crosses them. Skill A
(reads ~/.ssh to add a deploy key) and skill B (posts release notes to api.example.com) are
each fine alone. Together, a poisoned B can exfiltrate what A read — through the agent, not
through any process. These rules run at every activation against the session ledger.

Actions map onto Claude Code's PreToolUse ``permissionDecision``: allow | ask | deny.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import classes as C
from .lock import LockStatus
from .policy import Policy
from .session import Session

SEVERITY_ORDER = {"deny": 0, "ask": 1, "allow": 2}


@dataclass
class Finding:
    rule: str  # R1..R6
    code: str
    action: str  # allow | ask | deny
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "code": self.code, "action": self.action, "message": self.message, **({"detail": self.detail} if self.detail else {})}


@dataclass
class Decision:
    action: str
    findings: list[Finding]

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if f.action in ("deny", "ask")]

    def reason(self) -> str:
        if not self.blocking:
            return "no composition findings"
        return "; ".join(f"[{f.rule}] {f.message}" for f in self.blocking[:4])

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "findings": [f.to_dict() for f in self.findings]}


def _hosts_not_covered(new_hosts: list[str], allowed: set[str]) -> list[str]:
    """Hosts in ``new_hosts`` that no rule in ``allowed`` already permits (string-level)."""
    from .proxy import NetRule

    rules = []
    for a in allowed:
        try:
            rules.append(NetRule.parse(a))
        except Exception:
            continue
    out = []
    for h in new_hosts:
        try:
            nr = NetRule.parse(h)
        except Exception:
            out.append(h)
            continue
        host = nr.host if not nr.host.startswith("*.") else "x" + nr.host[1:]
        port = nr.port if nr.port not in (None, -1) else 443
        if not any(r.matches(host, port) for r in rules):
            out.append(h)
    return out


def evaluate_activation(
    policy: Policy,
    session: Session | None,
    lock_status: LockStatus | None,
    *,
    strict: bool = False,
    require_approval: bool = True,
) -> Decision:
    F: list[Finding] = []
    esc = "deny" if strict else "ask"

    # ---- R0: policy errors → deny (undeclared class contact etc.)
    for r in policy.errors:
        F.append(Finding("R0", r.code, "deny", r.message, r.detail))

    # ---- R5: rug-pull lock
    if lock_status is not None:
        if lock_status.status == "changed":
            F.append(Finding("R5", "content-changed", "deny", lock_status.describe(), {"changed": lock_status.changed, "added": lock_status.added, "removed": lock_status.removed}))
        elif lock_status.status == "unapproved" and require_approval:
            F.append(Finding("R5", "unapproved", esc, "skill has not been approved; review its manifest with `skilljail check` then `skilljail approve`"))

    touched = policy.classes_touched()
    declared_reads = (touched["read"] | touched["read_covers"]) & C.READ_SENSITIVE & policy.declared
    declared_writes = (touched["write"] | touched["write_covers"]) & C.WRITE_SENSITIVE & policy.declared

    # ---- R1: exfil chain across skills (either order)
    if session is not None:
        prior = session.all_seen()
        prior_reads = session.classes_read_so_far()
        prior_egress = session.egress_so_far()
        # new skill brings egress while the session already read secrets
        if prior_reads and policy.net_allow:
            readers = [s.name for s in prior if s.classes_read]
            # hosts the new skill can reach that no *reading* skill could
            reader_hosts: set[str] = set()
            for s in prior:
                if s.classes_read:
                    reader_hosts.update(s.net_allow)
            novel = _hosts_not_covered(policy.net_allow, reader_hosts)
            if novel:
                F.append(Finding("R1", "exfil-chain", esc,
                    f"session already read sensitive class(es) {sorted(prior_reads)} via {readers}; this skill adds egress to {novel} — the agent's context could carry secrets to a new destination",
                    {"prior_classes": sorted(prior_reads), "novel_hosts": novel, "readers": readers}))
        # new skill reads secrets while the session already has egress elsewhere
        if declared_reads and prior_egress:
            novel = _hosts_not_covered(sorted(prior_egress), set(policy.net_allow))
            if novel:
                F.append(Finding("R1", "exfil-chain", esc,
                    f"this skill reads sensitive class(es) {sorted(declared_reads)} while earlier skills in this session can reach {novel}",
                    {"classes": sorted(declared_reads), "prior_hosts": novel}))

    # ---- R2: persistence writes need an approved justification
    if declared_writes:
        approved = lock_status is not None and lock_status.status == "approved"
        if not approved:
            F.append(Finding("R2", "persistence-write", esc,
                f"skill declares writes to persistence-capable class(es) {sorted(declared_writes)}; approve the manifest to accept its justification",
                {"classes": sorted(declared_writes)}))
        else:
            F.append(Finding("R2", "persistence-write-approved", "allow", f"declared writes to {sorted(declared_writes)} accepted by approval"))

    # ---- R3: write→exec
    for r in policy.risks:
        if r.code in ("write-exec-overlap", "write-into-path"):
            F.append(Finding("R3", r.code, "deny", r.message, r.detail))

    # ---- R4: over-broad grants
    for r in policy.risks:
        if r.code in ("over-broad-read", "net-wildcard", "dangerous-exec"):
            F.append(Finding("R4", r.code, esc, r.message, r.detail))
        elif r.code == "over-broad-write":
            F.append(Finding("R4", r.code, "deny", r.message, r.detail))

    # ---- R6: secret-bearing env + egress (informational unless strict)
    secretish = [e for e in policy.env_pass if any(k in e.upper() for k in ("TOKEN", "SECRET", "KEY", "PASS", "CRED"))]
    if secretish and policy.net_allow:
        F.append(Finding("R6", "secret-env-with-egress", "allow" if not strict else "ask",
            f"credential-like env {secretish} is exposed to a skill with egress to {policy.net_allow}; ensure those hosts are the credential's legitimate consumers",
            {"env": secretish, "hosts": policy.net_allow}))

    action = "allow"
    for f in F:
        if SEVERITY_ORDER[f.action] < SEVERITY_ORDER[action]:
            action = f.action
    return Decision(action=action, findings=F)


def explain(decision: Decision) -> str:
    lines = [f"decision: {decision.action.upper()}"]
    for f in decision.findings:
        lines.append(f"  [{f.rule}:{f.action}] {f.message}")
    return "\n".join(lines)
