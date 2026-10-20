"""
Bayora Policy Gateway
=====================
The gateway is the ONLY path between teams and the Client LLM.
It enforces:
  1. Allowlist: which team may call which endpoint
  2. Rate limiting: per-team, per-evaluation request budgets
  3. Output filtering: canary string detection, exfiltration prevention
  4. Timing normalization: response-time padding to reduce side channels
  5. Request logging: all requests are logged for the audit trail

Network position:
  - Connected to net-red, net-blue, net-llm, and net-control
  - Red can reach gateway (but not blue or client-llm directly)
  - Blue can reach gateway (but not red or client-llm directly)
  - Gateway can reach client-llm, control-plane
"""

import os
import time
import asyncio
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://control-plane:8000")
CLIENT_LLM_URL = os.environ.get("CLIENT_LLM_URL", "http://client-llm:8000")
RED_URL = os.environ.get("RED_URL", "http://red:8000")
BLUE_URL = os.environ.get("BLUE_URL", "http://blue:8000")

# Timing normalization: pad responses to at least this many ms
TIMING_PAD_MS = int(os.environ.get("TIMING_PAD_MS", "100"))

# Rate limiting: max requests per team per minute
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "60"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("bayora.gateway")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
START_TIME = time.time()

# Rate limiter: team -> list of request timestamps
rate_buckets: dict[str, list[float]] = defaultdict(list)

# Canary strings to detect exfiltration attempts
CANARY_PATTERNS = [
    r"CANARY-[A-Z0-9]{8}",           # e.g. CANARY-ABC12345
    r"BLUE-SECRET-[A-Za-z0-9]+",     # Blue team secrets
    r"RED-SECRET-[A-Za-z0-9]+",      # Red team secrets
    r"BAYORA-CANARY-[A-Za-z0-9]+",   # System canaries
]

# Allowlist: which teams may access which services
# Format: (team) -> list of allowed target services
ALLOWLIST = {
    "red": ["client-llm"],   # Red can query the Client LLM (through gateway)
    "blue": ["client-llm"],  # Blue can query the Client LLM (through gateway)
    "admin": ["client-llm", "red", "blue"],  # Admin can reach everything
}

# Service URL mapping
SERVICE_URLS = {
    "client-llm": CLIENT_LLM_URL,
    "red": RED_URL,
    "blue": BLUE_URL,
    "control-plane": CONTROL_PLANE_URL,
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class HealthResponse(BaseModel):
    service: str = "gateway"
    status: str = "healthy"
    version: str = "0.1.0"
    uptime_seconds: float
    container_security: dict


class PolicyDecision(BaseModel):
    allowed: bool
    reason: str
    team: str
    target: str
    timestamp: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_container_security_info() -> dict:
    """Report the security posture of this container."""
    info = {
        "uid": os.getuid() if hasattr(os, "getuid") else "N/A",
        "gid": os.getgid() if hasattr(os, "getgid") else "N/A",
        "pid": os.getpid(),
        "read_only_fs": not os.access("/", os.W_OK),
    }
    try:
        with open("/proc/1/status", "r") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    val = line.strip().split()[-1]
                    info["seccomp_mode"] = {"0": "disabled", "1": "strict", "2": "filter"}.get(val, val)
                elif line.startswith("NoNewPrivs:"):
                    info["no_new_privs"] = line.strip().split()[-1] == "1"
    except FileNotFoundError:
        pass
    return info


def check_rate_limit(team: str) -> bool:
    """Check if the team is within its rate limit. Returns True if allowed."""
    now = time.time()
    window_start = now - 60
    # Prune old entries
    rate_buckets[team] = [t for t in rate_buckets[team] if t > window_start]
    if len(rate_buckets[team]) >= RATE_LIMIT_PER_MINUTE:
        return False
    rate_buckets[team].append(now)
    return True


def check_canary_leakage(content: str) -> list[str]:
    """Scan response content for canary strings that should not be exfiltrated."""
    found = []
    for pattern in CANARY_PATTERNS:
        matches = re.findall(pattern, content)
        found.extend(matches)
    return found


def check_allowlist(team: str, target_service: str) -> bool:
    """Check if the team is allowed to access the target service."""
    allowed_targets = ALLOWLIST.get(team, [])
    return target_service in allowed_targets


async def report_event(event_type: str, team: str, details: dict):
    """Report a policy event to the control plane's audit log."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"{CONTROL_PLANE_URL}/audit/events",
                json={
                    "event_type": event_type,
                    "team": team,
                    "details": details,
                },
                # Use first available admin token (in production, gateway has its own service token)
                headers={"Authorization": "Bearer gateway-internal"},
            )
    except Exception as e:
        logger.warning(f"Failed to report audit event: {e}")


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Bayora Policy Gateway",
    description="Policy enforcement gateway — the only path between teams and the Client LLM",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health_check():
    return HealthResponse(
        uptime_seconds=round(time.time() - START_TIME, 2),
        container_security=get_container_security_info(),
    )


@app.get("/security", tags=["system"])
async def security_info():
    return {
        "service": "gateway",
        "security": get_container_security_info(),
        "policy": {
            "rate_limit_per_minute": RATE_LIMIT_PER_MINUTE,
            "timing_pad_ms": TIMING_PAD_MS,
            "canary_patterns": CANARY_PATTERNS,
            "allowlist": ALLOWLIST,
        },
    }


# ---------------------------------------------------------------------------
# Policy proxy: route team requests to the appropriate service
# ---------------------------------------------------------------------------
@app.api_route("/{team}/{target_service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"], tags=["proxy"])
async def policy_proxy(team: str, target_service: str, path: str, request: Request):
    """
    Route a team's request through policy enforcement to the target service.

    Enforcement pipeline:
    1. Allowlist check (is this team allowed to reach this service?)
    2. Rate limit check
    3. Forward request to target service
    4. Output filtering (canary leakage detection)
    5. Timing normalization (pad response time)
    """
    start_time = time.time()
    timestamp = datetime.now(timezone.utc).isoformat()

    # --- 1. Allowlist check ---
    if not check_allowlist(team, target_service):
        logger.warning(f"POLICY VIOLATION: {team} tried to access {target_service}")
        await report_event("policy.access_denied", team, {
            "target_service": target_service,
            "path": path,
            "reason": "not in allowlist",
        })
        raise HTTPException(
            status_code=403,
            detail=f"Team '{team}' is not allowed to access service '{target_service}'",
        )

    # --- 2. Rate limit check ---
    if not check_rate_limit(team):
        logger.warning(f"RATE LIMIT: {team} exceeded {RATE_LIMIT_PER_MINUTE} req/min")
        await report_event("policy.rate_limited", team, {
            "target_service": target_service,
            "limit": RATE_LIMIT_PER_MINUTE,
        })
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {RATE_LIMIT_PER_MINUTE} requests per minute",
        )

    # --- 3. Forward request ---
    target_url = SERVICE_URLS.get(target_service)
    if not target_url:
        raise HTTPException(status_code=404, detail=f"Unknown service: {target_service}")

    body = await request.body()
    forward_headers = {
        "X-Bayora-Team": team,
        "X-Bayora-Timestamp": timestamp,
    }
    # Forward authorization header if present
    auth_header = request.headers.get("Authorization")
    if auth_header:
        forward_headers["Authorization"] = auth_header

    # Forward content-type
    ct = request.headers.get("content-type")
    if ct:
        forward_headers["Content-Type"] = ct

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.request(
                method=request.method,
                url=f"{target_url}/{path}",
                content=body,
                headers=forward_headers,
            )
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail=f"Cannot reach {target_service}")

    response_body = resp.text

    # --- 4. Output filtering (canary leakage detection) ---
    leaked_canaries = check_canary_leakage(response_body)
    if leaked_canaries:
        logger.critical(f"CANARY LEAKAGE DETECTED: {team} -> {target_service}: {leaked_canaries}")
        await report_event("security.canary_leaked", team, {
            "target_service": target_service,
            "canaries": leaked_canaries,
            "path": path,
        })
        # Block the response — do NOT forward leaked content
        raise HTTPException(
            status_code=451,
            detail="Response blocked: potential data exfiltration detected",
        )

    # --- 5. Timing normalization (pad response to reduce side channels) ---
    elapsed_ms = (time.time() - start_time) * 1000
    if elapsed_ms < TIMING_PAD_MS:
        await asyncio.sleep((TIMING_PAD_MS - elapsed_ms) / 1000)

    # Log successful request
    logger.info(f"PROXY: {team} -> {target_service}/{path} [{resp.status_code}] {elapsed_ms:.1f}ms")

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type"),
    )


# ---------------------------------------------------------------------------
# Direct connectivity test endpoint
# ---------------------------------------------------------------------------
@app.get("/test/connectivity/{target}", tags=["test"])
async def test_connectivity(target: str):
    """
    Test if the gateway can reach a target service.
    Used by isolation tests to verify network segmentation.
    """
    url = SERVICE_URLS.get(target)
    if not url:
        return {"target": target, "reachable": False, "error": "unknown service"}

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{url}/health")
            return {
                "target": target,
                "reachable": True,
                "status_code": resp.status_code,
                "url": url,
            }
    except Exception as e:
        return {
            "target": target,
            "reachable": False,
            "error": str(e),
            "url": url,
        }


# ---------------------------------------------------------------------------
# Rate limit status
# ---------------------------------------------------------------------------
@app.get("/rate-limits", tags=["system"])
async def get_rate_limits():
    """Show current rate limit counters per team."""
    now = time.time()
    window_start = now - 60
    return {
        team: len([t for t in timestamps if t > window_start])
        for team, timestamps in rate_buckets.items()
    }
