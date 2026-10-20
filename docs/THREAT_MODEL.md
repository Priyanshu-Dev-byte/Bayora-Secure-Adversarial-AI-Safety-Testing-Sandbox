# Bayora — Threat Model

## Document Status
| Version | Date | Author |
|---------|------|--------|
| 1.0 | 2026-10-20 | Dark Panthers |

## 1. Overview

Bayora is a **Secure Adversarial AI Testing Sandbox** that isolates Red Team
(adversarial prompt attackers), Blue Team (defensive countermeasures), and a
Client LLM (model under test) in separate containers with no direct network
path between Red and Blue, and the Client LLM reachable only through a
policy-enforcing gateway.

## 2. Assets

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Red team adversarial prompts | Medium | Red container (`/app/scratch`) |
| Blue team defense rules & classifier weights | High | Blue container (`/app/scratch`) |
| Client LLM model weights/config | High | Client LLM container |
| Per-session context & KV-cache | High | Client LLM container memory |
| Audit log (hash chain) | Critical | PostgreSQL (control plane) |
| HMAC signing key | Critical | Control plane env (tmpfs) |
| JWT signing secret | Critical | Control plane env (tmpfs) |
| Evaluation results & reports | Medium | Control plane / export |
| Canary strings | Medium | Deployed across services |

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│ HOST KERNEL (TRUSTED)                                    │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ net-red      │  │ net-control  │  │ net-blue     │   │
│  │  ┌────────┐  │  │  ┌────────┐  │  │  ┌────────┐  │   │
│  │  │  RED   │──┼──┼─▶│GATEWAY │──┼──┼──│  BLUE  │  │   │
│  │  └────────┘  │  │  └───┬────┘  │  │  └────────┘  │   │
│  └──────────────┘  │      │       │  └──────────────┘   │
│                    │      ▼       │                      │
│  ┌──────────────┐  │ ┌────────┐   │                      │
│  │ net-llm      │  │ │CONTROL │   │                      │
│  │  ┌────────┐  │  │ │ PLANE  │   │                      │
│  │  │CLIENT  │◀─┼──┤ └───┬────┘  │                      │
│  │  │  LLM   │  │  │     │       │                      │
│  │  └────────┘  │  │     ▼       │                      │
│  └──────────────┘  │ ┌────────┐   │                      │
│                    │ │POSTGRES│   │                      │
│                    │ └────────┘   │                      │
│                    └──────────────┘                      │
└─────────────────────────────────────────────────────────┘
```

**Trust boundary 1 (TB1):** Red container ↔ Gateway (net-red)
**Trust boundary 2 (TB2):** Blue container ↔ Gateway (net-blue)
**Trust boundary 3 (TB3):** Gateway ↔ Client LLM (net-llm)
**Trust boundary 4 (TB4):** Control Plane ↔ PostgreSQL (net-control)
**Trust boundary 5 (TB5):** Host kernel ↔ All containers

## 4. Adversary Model

| Adversary | Capability | Goal |
|-----------|-----------|------|
| Malicious Red operator | Full control of Red container processes | Steal Blue's defense rules, poison audit log, access LLM without policy enforcement |
| Malicious Blue operator | Full control of Blue container processes | Steal Red's attack prompts, manipulate evaluation results |
| External attacker | Network access to exposed ports (8000, 3000) | Compromise control plane, exfiltrate data |
| Insider (rogue admin) | Valid admin credentials | Tamper with audit records undetected |

## 5. Threats and Controls

| ID | Threat | Attack Vector | Control | Status | Test |
|----|--------|--------------|---------|--------|------|
| T1 | Red reads Blue's data | Direct network access Red→Blue | Network isolation: separate Docker networks, no shared network | IMPLEMENTED | `test_network_isolation_red` |
| T2 | Blue reads Red's data | Direct network access Blue→Red | Network isolation: separate Docker networks | IMPLEMENTED | `test_network_isolation_blue` |
| T3 | Red bypasses gateway to reach LLM | Direct network access Red→LLM | Client LLM on net-llm only, Red on net-red only | IMPLEMENTED | `test_network_isolation_red` (LLM direct) |
| T4 | Cross-team token reuse | Red uses stolen Blue token | Scoped capability tokens with team binding | IMPLEMENTED | `test_cross_team_access_denied` |
| T5 | Cross-session context leak | Red queries LLM about Blue's session | Per-session context isolation in Client LLM | IMPLEMENTED | `test_llm_context_isolation` |
| T6 | KV-cache timing side channel | Red infers Blue's queries via cache hit timing | Per-tenant KV-cache namespace + timing normalization | IMPLEMENTED | `test/timing` endpoint |
| T7 | Audit log tampering | Modify audit records to hide attacks | Hash-chain with HMAC signatures | IMPLEMENTED | `test_audit_tamper_detection` |
| T8 | Canary string exfiltration | LLM leaks embedded canary in response | Gateway output filtering with pattern matching | IMPLEMENTED | Attack simulation canary checks |
| T9 | Container escape | Exploit kernel vulnerability | cap_drop ALL, seccomp, no-new-privileges, read-only FS, resource limits | PARTIAL | `check-security.sh` verifies settings |
| T10 | Privilege escalation inside container | Exploit setuid binary or capability | Non-root user, no capabilities, no-new-privileges | IMPLEMENTED | Security info endpoints |
| T11 | Resource exhaustion (DoS) | Fork bomb or memory exhaustion | PID limits (64), memory limits (256MB), CPU limits | IMPLEMENTED | Docker inspect verification |
| T12 | Rate limit bypass | Flood gateway with requests | Per-team rate limiting at gateway | IMPLEMENTED | Rate limit counter verification |
| T13 | Prompt injection via gateway | Inject malicious headers or parameters | Input validation, typed request models, allowlist | IMPLEMENTED | Blue classifier tests |

## 6. What This Architecture Protects Against

1. **Cross-team data leakage via network** — Red and Blue share no network;
   the only communication path is through the gateway.

2. **Direct LLM access** — The Client LLM is on a private network reachable
   only by the gateway, which enforces allowlists and rate limits.

3. **Cross-session context contamination** — Per-session context isolation in
   the Client LLM prevents one team from seeing another's prompts/responses.

4. **KV-cache side channels** — Per-tenant cache namespaces prevent cache
   timing attacks. Response-time normalization (padding) reduces measurable
   timing differences.

5. **Audit log tampering** — Hash-chain integrity with HMAC signatures ensures
   any modification to audit records is detectable.

6. **Canary/secret exfiltration** — Gateway output filtering blocks responses
   containing canary patterns, preventing data leakage through the LLM.

7. **Container breakout difficulty** — Minimal capabilities, seccomp profiles,
   read-only filesystem, and resource limits significantly raise the bar for
   container escape.

## 7. What This Architecture Does NOT Protect Against

> [!CAUTION]
> These are acknowledged residual risks. They are reduced but NOT eliminated.

### 7.1 Kernel Escapes
**Condition of failure:** A vulnerability in the Linux kernel (or the container
runtime) allows an attacker to escape the container and access the host.

**Mitigation:** This is a fundamental limitation of OS-level containers. The
seccomp profile blocks many syscalls used in known escapes, and dropping all
capabilities removes most privilege escalation paths. However, a zero-day
kernel vulnerability could bypass these controls.

**Future work:** gVisor or Kata Containers provide a second layer of isolation
(user-space kernel or VM-based) that would survive most kernel escapes.

### 7.2 Host Compromise
**Condition of failure:** An attacker gains access to the host machine
(physical or SSH).

**Mitigation:** Out of scope — we assume a trusted host kernel and cloud IAM.
In production, host hardening (SELinux, AppArmor, CIS benchmarks) and
confidential computing (SGX/SEV/TDX) would be deployed.

### 7.3 Residual Timing Side Channels
**Condition of failure:** Despite timing normalization, a sophisticated
attacker may still extract information from microarchitectural timing
differences (cache lines, branch prediction, etc.).

**Mitigation:** Response-time padding reduces application-level timing leaks.
The real measured numbers are reported honestly (see timing test results).
Complete elimination requires hardware-level isolation (separate physical
machines or confidential computing).

### 7.4 Sophisticated Prompt Injection
**Condition of failure:** The mock LLM uses pattern matching, not a real ML
model. Advanced jailbreak techniques may not trigger our pattern-based
defenses.

**Mitigation:** The Blue team classifier is a demonstration of the defense
framework. In production, this would be a trained ML classifier with
continual adversarial fine-tuning.

### 7.5 Docker Socket Exposure
**Condition of failure:** If the control plane were given Docker socket access
for dynamic provisioning, a compromise of the control plane would give full
host control.

**Mitigation:** The current design does NOT mount the Docker socket.
Containers are pre-provisioned via compose. Dynamic provisioning is PROPOSED
as a future feature with appropriate sandboxing (rootless Docker, Podman).

## 8. Assumptions

1. The host kernel is trusted and up to date
2. Cloud IAM (if deployed) is correctly configured
3. Docker Desktop / Docker Engine is running with default security settings
4. The seccomp profile and capability restrictions are correctly applied
5. Network isolation relies on Docker's bridge network implementation
6. HMAC and JWT secrets are not committed to version control

## 9. Future Work

| Feature | Benefit | Status |
|---------|---------|--------|
| gVisor runtime | User-space kernel prevents kernel escapes | PROPOSED |
| Kata Containers | VM-level isolation per container | PROPOSED |
| Confidential computing (SGX/SEV) | Hardware-enforced memory isolation | PROPOSED |
| Kubernetes deployment | Production orchestration with network policies | PROPOSED |
| eBPF monitoring | Kernel-level syscall tracing without overhead | PROPOSED |
| mTLS between services | Encrypted and authenticated service-to-service communication | PROPOSED |
| Formal verification | Prove isolation properties mathematically | PROPOSED |
| Real ML classifier | Replace pattern matching with trained model | PROPOSED |
| Hardware security modules | HSM-backed key management for HMAC/JWT | PROPOSED |
