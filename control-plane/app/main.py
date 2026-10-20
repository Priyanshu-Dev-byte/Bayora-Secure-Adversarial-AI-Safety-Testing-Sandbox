"""
Bayora Control Plane — FastAPI Backend
======================================
Central orchestration service for the Bayora Secure Adversarial AI Testing
Sandbox. Handles authentication, evaluation lifecycle, audit logging, and
report export.

API path: Dashboard → Control Plane → Gateway → Sandbox Containers
"""

import os
import time
import uuid
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import httpx

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")
HMAC_SECRET = os.environ.get("HMAC_SECRET", "dev-hmac-secret")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://gateway:8000")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("bayora.control-plane")

# ---------------------------------------------------------------------------
# In-memory stores (Phase 1 stubs — replaced with Postgres in Phase 4)
# ---------------------------------------------------------------------------
# Evaluations: evaluation_id -> {metadata}
evaluations: dict[str, dict] = {}

# Audit log: append-only list of events (replaced with Postgres hash-chain in Phase 4)
audit_log: list[dict] = []

# Users/tokens: token -> {team, scope, evaluation_id, expires}
tokens: dict[str, dict] = {}

# Pre-seeded demo users (replaced with proper auth in Phase 3)
DEMO_USERS = {
    "admin": {"password": "admin", "role": "admin", "team": "admin"},
    "red-operator": {"password": "redteam", "role": "operator", "team": "red"},
    "blue-operator": {"password": "blueteam", "role": "operator", "team": "blue"},
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    team: str
    role: str
    expires_at: str


class EvaluationCreate(BaseModel):
    name: str
    description: str = ""


class EvaluationResponse(BaseModel):
    evaluation_id: str
    name: str
    description: str
    status: str
    created_at: str


class AuditEvent(BaseModel):
    event_type: str
    team: str
    evaluation_id: str = ""
    details: dict = Field(default_factory=dict)


class AuditRecord(BaseModel):
    sequence: int
    timestamp: str
    event_type: str
    team: str
    evaluation_id: str
    details: dict
    prev_hash: str
    record_hash: str
    hmac_signature: str


class HealthResponse(BaseModel):
    service: str = "control-plane"
    status: str = "healthy"
    version: str = "0.1.0"
    uptime_seconds: float
    container_security: dict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
START_TIME = time.time()


def get_container_security_info() -> dict:
    """Report the security posture of this container at runtime."""
    info = {
        "uid": os.getuid() if hasattr(os, "getuid") else "N/A (Windows)",
        "gid": os.getgid() if hasattr(os, "getgid") else "N/A (Windows)",
        "pid": os.getpid(),
        "read_only_fs": not os.access("/", os.W_OK),
    }
    # Check /proc/1/status for seccomp and capabilities
    try:
        with open("/proc/1/status", "r") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    val = line.strip().split()[-1]
                    info["seccomp_mode"] = {"0": "disabled", "1": "strict", "2": "filter"}.get(val, val)
                elif line.startswith("CapEff:"):
                    info["effective_capabilities"] = line.strip().split()[-1]
                elif line.startswith("NoNewPrivs:"):
                    info["no_new_privs"] = line.strip().split()[-1] == "1"
    except FileNotFoundError:
        info["proc_status"] = "not available"
    return info


def compute_record_hash(record_data: dict) -> str:
    """Compute SHA-256 hash of an audit record's content."""
    canonical = json.dumps(record_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def compute_hmac(data: str) -> str:
    """Compute HMAC-SHA256 signature for audit integrity."""
    return hmac.new(
        HMAC_SECRET.encode(),
        data.encode(),
        hashlib.sha256,
    ).hexdigest()


def append_audit_event(event_type: str, team: str, evaluation_id: str = "", details: dict | None = None) -> dict:
    """Append a new event to the audit log with hash chaining."""
    details = details or {}
    sequence = len(audit_log)
    prev_hash = audit_log[-1]["record_hash"] if audit_log else "0" * 64

    record_data = {
        "sequence": sequence,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "team": team,
        "evaluation_id": evaluation_id,
        "details": details,
        "prev_hash": prev_hash,
    }

    record_hash = compute_record_hash(record_data)
    record_data["record_hash"] = record_hash
    record_data["hmac_signature"] = compute_hmac(record_hash)

    audit_log.append(record_data)
    logger.info(f"AUDIT [{sequence}] {event_type} team={team} eval={evaluation_id}")
    return record_data


def generate_token(team: str, role: str, evaluation_id: str = "", ttl_minutes: int = 60) -> tuple[str, str]:
    """Generate a scoped capability token (Phase 1: simple random token, Phase 3: JWT)."""
    token = f"bayora_{team}_{uuid.uuid4().hex[:16]}"
    expires = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
    tokens[token] = {
        "team": team,
        "role": role,
        "evaluation_id": evaluation_id,
        "expires": expires.isoformat(),
        "created": datetime.now(timezone.utc).isoformat(),
    }
    return token, expires.isoformat()


def validate_token(authorization: str = Header(default="")) -> dict:
    """Validate a bearer token and return its claims."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    claims = tokens.get(token)
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid token")
    if datetime.fromisoformat(claims["expires"]) < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Token expired")
    return claims


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    logger.info("Bayora Control Plane starting...")
    append_audit_event("system.startup", "system", details={"service": "control-plane"})

    # Pre-generate demo tokens for convenience
    for username, user in DEMO_USERS.items():
        token, expires = generate_token(user["team"], user["role"], ttl_minutes=1440)  # 24h for dev
        logger.info(f"Demo token for {username} ({user['team']}): {token}")

    yield
    logger.info("Bayora Control Plane shutting down.")


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Bayora Control Plane",
    description="Secure Adversarial AI Testing Sandbox — Central Orchestration",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — allow dashboard access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health & Security Endpoints
# ---------------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health_check():
    """Health check endpoint — also reports container security posture."""
    return HealthResponse(
        uptime_seconds=round(time.time() - START_TIME, 2),
        container_security=get_container_security_info(),
    )


@app.get("/security", tags=["system"])
async def security_info():
    """Detailed security posture report for this container."""
    return {
        "service": "control-plane",
        "security": get_container_security_info(),
        "environment": {
            "database_configured": bool(DATABASE_URL),
            "jwt_secret_default": JWT_SECRET == "dev-secret",
            "hmac_secret_default": HMAC_SECRET == "dev-hmac-secret",
        },
    }


# ---------------------------------------------------------------------------
# Auth Endpoints (Phase 1 stubs — expanded in Phase 3)
# ---------------------------------------------------------------------------
@app.post("/auth/login", response_model=LoginResponse, tags=["auth"])
async def login(req: LoginRequest):
    """Authenticate and receive a scoped capability token."""
    user = DEMO_USERS.get(req.username)
    if not user or user["password"] != req.password:
        append_audit_event("auth.login_failed", "unknown", details={"username": req.username})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token, expires = generate_token(user["team"], user["role"])
    append_audit_event("auth.login", user["team"], details={"username": req.username})
    return LoginResponse(token=token, team=user["team"], role=user["role"], expires_at=expires)


# ---------------------------------------------------------------------------
# Evaluation Endpoints
# ---------------------------------------------------------------------------
@app.post("/evaluations", response_model=EvaluationResponse, tags=["evaluations"])
async def create_evaluation(req: EvaluationCreate, claims: dict = Depends(validate_token)):
    """Create a new evaluation — provisions isolated sandboxes."""
    if claims["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create evaluations")

    eval_id = f"eval_{uuid.uuid4().hex[:12]}"
    evaluation = {
        "evaluation_id": eval_id,
        "name": req.name,
        "description": req.description,
        "status": "provisioned",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": claims["team"],
    }
    evaluations[eval_id] = evaluation

    append_audit_event("evaluation.created", claims["team"], eval_id, {"name": req.name})
    return EvaluationResponse(**evaluation)


@app.get("/evaluations", tags=["evaluations"])
async def list_evaluations(claims: dict = Depends(validate_token)):
    """List evaluations visible to the current user."""
    return list(evaluations.values())


@app.get("/evaluations/{evaluation_id}", tags=["evaluations"])
async def get_evaluation(evaluation_id: str, claims: dict = Depends(validate_token)):
    """Get evaluation details."""
    if evaluation_id not in evaluations:
        raise HTTPException(status_code=404, detail="Evaluation not found")
    return evaluations[evaluation_id]


# ---------------------------------------------------------------------------
# Audit Endpoints (Phase 1 in-memory — Phase 4 adds Postgres + verify)
# ---------------------------------------------------------------------------
@app.get("/audit", tags=["audit"])
async def get_audit_log(
    team: Optional[str] = None,
    evaluation_id: Optional[str] = None,
    claims: dict = Depends(validate_token),
):
    """Query the audit log. Non-admin users see only their team's events."""
    log = audit_log

    # Non-admin users can only see their own team's events
    if claims["role"] != "admin":
        log = [r for r in log if r["team"] == claims["team"] or r["team"] == "system"]

    if team:
        log = [r for r in log if r["team"] == team]
    if evaluation_id:
        log = [r for r in log if r["evaluation_id"] == evaluation_id]

    return log


@app.post("/audit/events", tags=["audit"])
async def record_audit_event(event: AuditEvent, claims: dict = Depends(validate_token)):
    """Record an audit event (typically called by other services via the gateway)."""
    record = append_audit_event(
        event.event_type, event.team, event.evaluation_id, event.details
    )
    return record


@app.get("/audit/verify", tags=["audit"])
async def verify_audit_chain(claims: dict = Depends(validate_token)):
    """Verify the integrity of the audit hash chain."""
    if claims["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can verify the audit chain")

    if not audit_log:
        return {"valid": True, "records_checked": 0, "message": "Audit log is empty"}

    for i, record in enumerate(audit_log):
        # Check prev_hash linkage
        expected_prev = audit_log[i - 1]["record_hash"] if i > 0 else "0" * 64
        if record["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "first_tampered_record": i,
                "message": f"Hash chain broken at record {i}: prev_hash mismatch",
            }

        # Recompute hash
        record_data = {k: v for k, v in record.items() if k not in ("record_hash", "hmac_signature")}
        expected_hash = compute_record_hash(record_data)
        if record["record_hash"] != expected_hash:
            return {
                "valid": False,
                "first_tampered_record": i,
                "message": f"Hash mismatch at record {i}: content was modified",
            }

        # Verify HMAC
        expected_hmac = compute_hmac(record["record_hash"])
        if record["hmac_signature"] != expected_hmac:
            return {
                "valid": False,
                "first_tampered_record": i,
                "message": f"HMAC verification failed at record {i}: signature invalid",
            }

    return {
        "valid": True,
        "records_checked": len(audit_log),
        "message": f"All {len(audit_log)} records verified successfully",
    }


# ---------------------------------------------------------------------------
# Audit tamper demo endpoint (for demonstration only)
# ---------------------------------------------------------------------------
@app.post("/audit/demo-tamper/{sequence}", tags=["audit", "demo"])
async def demo_tamper_record(sequence: int, new_team: str = "hacked", claims: dict = Depends(validate_token)):
    """
    DEMO ONLY: Tamper with an audit record to demonstrate verification failure.
    Modifies the team field of the specified record without updating the hash.
    """
    if claims["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can use demo endpoints")
    if sequence < 0 or sequence >= len(audit_log):
        raise HTTPException(status_code=404, detail="Record not found")

    original_team = audit_log[sequence]["team"]
    audit_log[sequence]["team"] = new_team

    return {
        "message": f"Record {sequence} tampered: team changed from '{original_team}' to '{new_team}'",
        "note": "Run /audit/verify to detect this tampering",
    }


# ---------------------------------------------------------------------------
# Gateway proxy endpoint (for dashboard to trigger actions on sandboxes)
# ---------------------------------------------------------------------------
@app.post("/proxy/{team}/{path:path}", tags=["proxy"])
async def proxy_to_gateway(team: str, path: str, request: Request, claims: dict = Depends(validate_token)):
    """Proxy requests from the dashboard through the gateway to sandbox containers."""
    if claims["role"] != "admin" and claims["team"] != team:
        append_audit_event("access.denied", claims["team"], details={
            "target_team": team,
            "path": path,
            "reason": "cross-team access denied"
        })
        raise HTTPException(status_code=403, detail=f"Team '{claims['team']}' cannot access team '{team}'")

    body = await request.body()
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=f"{GATEWAY_URL}/{team}/{path}",
                content=body,
                headers={"Authorization": request.headers.get("Authorization", "")},
            )
            return Response(content=resp.content, status_code=resp.status_code,
                           media_type=resp.headers.get("content-type"))
        except httpx.ConnectError:
            raise HTTPException(status_code=502, detail=f"Cannot reach gateway at {GATEWAY_URL}")


# ---------------------------------------------------------------------------
# Topology / Status endpoint (for admin dashboard)
# ---------------------------------------------------------------------------
@app.get("/topology", tags=["system"])
async def get_topology(claims: dict = Depends(validate_token)):
    """Return the current sandbox topology and service status."""
    if claims["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view topology")

    services = {
        "control-plane": {"network": "net-control", "status": "running", "port": 8000},
        "gateway": {"network": "net-red, net-blue, net-llm, net-control", "status": "unknown", "port": 8000},
        "red": {"network": "net-red", "status": "unknown", "port": 8000},
        "blue": {"network": "net-blue", "status": "unknown", "port": 8000},
        "client-llm": {"network": "net-llm", "status": "unknown", "port": 8000},
        "postgres": {"network": "net-control", "status": "unknown", "port": 5432},
    }

    # Probe gateway health
    async with httpx.AsyncClient(timeout=5) as client:
        for svc in ["gateway"]:
            try:
                resp = await client.get(f"{GATEWAY_URL}/health")
                if resp.status_code == 200:
                    services[svc]["status"] = "running"
            except Exception:
                services[svc]["status"] = "unreachable"

    return {
        "services": services,
        "networks": {
            "net-red": {"type": "internal", "members": ["red", "gateway"]},
            "net-blue": {"type": "internal", "members": ["blue", "gateway"]},
            "net-llm": {"type": "internal", "members": ["client-llm", "gateway"]},
            "net-control": {"type": "bridge", "members": ["control-plane", "gateway", "postgres"]},
        },
        "isolation_invariant": "Red and Blue share NO network. Client LLM reachable only through gateway.",
    }
