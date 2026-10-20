/**
 * Bayora API Client & Cryptographic Audit Engine
 * Automatically routes to real FastAPI backend (http://localhost:8000) if online,
 * or runs an in-browser high-fidelity cryptographic simulator with real SHA-256 + HMAC.
 */

const BACKEND_URL = "http://localhost:8000";

// Compute real Web Crypto SHA-256
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Compute real HMAC-SHA256
async function hmacSha256(keyStr, dataStr) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(keyStr),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, enc.encode(dataStr));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

const HMAC_SECRET = "bayora-hack-in-hills-2026-secret";

// In-browser fallback state
let simulatedAuditLog = [];
let simulatedCanaries = [
  { id: "canary-01", token: "BLUE-SECRET-9481-ALPHA", created: "2026-10-20 18:00:00", status: "Active / Monitored", triggers: 0 },
  { id: "canary-02", token: "CANARY-X781A-SYSTEM", created: "2026-10-20 18:15:00", status: "Active / Monitored", triggers: 0 },
];

export async function initSimulatedAuditChain() {
  if (simulatedAuditLog.length > 0) return simulatedAuditLog;

  const initialEvents = [
    { event_type: "system.startup", team: "system", details: { service: "control-plane", seccomp: "strict", cap_drop: "ALL" } },
    { event_type: "network.enclaves_provisioned", team: "system", details: { networks: ["net-red", "net-blue", "net-llm"], isolation: "verified" } },
    { event_type: "auth.login", team: "red", details: { username: "red-operator", role: "operator", ip: "172.28.1.10" } },
    { event_type: "policy.rule_loaded", team: "blue", details: { rule: "canary_filter", pattern: "BLUE-SECRET-*" } },
    { event_type: "eval.prompt_dispatched", team: "red", details: { target: "client-llm", sanitized: true, jitter_ms: 104 } },
  ];

  let prevHash = "0000000000000000000000000000000000000000000000000000000000000000";
  const records = [];

  for (let i = 0; i < initialEvents.length; i++) {
    const ev = initialEvents[i];
    const timestamp = new Date(Date.now() - (5 - i) * 120000).toISOString();
    const rawData = JSON.stringify({
      sequence: i,
      timestamp,
      event_type: ev.event_type,
      team: ev.team,
      evaluation_id: "eval-bayora-01",
      details: ev.details,
      prev_hash: prevHash,
    });

    const recordHash = await sha256(rawData);
    const signature = await hmacSha256(HMAC_SECRET, recordHash);

    const record = {
      sequence: i,
      timestamp,
      event_type: ev.event_type,
      team: ev.team,
      evaluation_id: "eval-bayora-01",
      details: ev.details,
      prev_hash: prevHash,
      record_hash: recordHash,
      hmac_signature: signature,
      is_tampered: false,
    };

    records.push(record);
    prevHash = recordHash;
  }

  simulatedAuditLog = records;
  return simulatedAuditLog;
}

export const BayoraAPI = {
  // Check if live backend is online
  async checkHealth() {
    try {
      const res = await fetch(`${BACKEND_URL}/health`, { method: "GET", signal: AbortSignal.timeout(1500) });
      if (res.ok) {
        const data = await res.json();
        return { online: true, data };
      }
    } catch {
      // Backend not running yet
    }
    return {
      online: false,
      data: {
        service: "control-plane",
        status: "healthy (simulated sandbox)",
        version: "0.1.0",
        uptime_seconds: 1420.5,
        container_security: {
          uid: 1000,
          gid: 1000,
          read_only_fs: true,
          seccomp_mode: "filter (SCMP_ACT_ERRNO)",
          effective_capabilities: "0000000000000400 (NET_BIND_SERVICE)",
          no_new_privs: true
        }
      }
    };
  },

  // Fetch Audit Log
  async getAuditLog() {
    try {
      const res = await fetch(`${BACKEND_URL}/audit`, {
        headers: { "Authorization": "Bearer bayora_admin_dev_token" },
        signal: AbortSignal.timeout(1500)
      });
      if (res.ok) return await res.json();
    } catch {
      // Fallback
    }
    if (simulatedAuditLog.length === 0) {
      await initSimulatedAuditChain();
    }
    return [...simulatedAuditLog];
  },

  // Append new event
  async appendAuditEvent(event_type, team, details) {
    if (simulatedAuditLog.length === 0) {
      await initSimulatedAuditChain();
    }

    const sequence = simulatedAuditLog.length;
    const prevHash = simulatedAuditLog.length > 0 ? simulatedAuditLog[simulatedAuditLog.length - 1].record_hash : "0".repeat(64);
    const timestamp = new Date().toISOString();

    const rawData = JSON.stringify({
      sequence,
      timestamp,
      event_type,
      team,
      evaluation_id: "eval-bayora-01",
      details,
      prev_hash: prevHash,
    });

    const recordHash = await sha256(rawData);
    const signature = await hmacSha256(HMAC_SECRET, recordHash);

    const record = {
      sequence,
      timestamp,
      event_type,
      team,
      evaluation_id: "eval-bayora-01",
      details,
      prev_hash: prevHash,
      record_hash: recordHash,
      hmac_signature: signature,
      is_tampered: false,
    };

    simulatedAuditLog.push(record);
    return record;
  },

  // Cryptographically verify chain
  async verifyChain(logToVerify) {
    const list = logToVerify || simulatedAuditLog;
    if (!list || list.length === 0) return { valid: true, message: "Chain is empty", count: 0 };

    for (let i = 0; i < list.length; i++) {
      const item = list[i];
      const expectedPrev = i === 0 ? "0".repeat(64) : list[i - 1].record_hash;

      if (item.prev_hash !== expectedPrev) {
        return {
          valid: false,
          brokenIndex: i,
          reason: `Chain Link Severed: Block #${i} prev_hash does not match hash of Block #${i - 1}.`
        };
      }

      // Re-hash data
      const rawData = JSON.stringify({
        sequence: item.sequence,
        timestamp: item.timestamp,
        event_type: item.event_type,
        team: item.team,
        evaluation_id: item.evaluation_id,
        details: item.details,
        prev_hash: item.prev_hash,
      });

      const recomputedHash = await sha256(rawData);
      if (item.record_hash !== recomputedHash) {
        return {
          valid: false,
          brokenIndex: i,
          reason: `Content Tampered: Payload inside Block #${i} was secretly altered. Digest mismatch!`
        };
      }

      // Re-verify HMAC
      const recomputedHmac = await hmacSha256(HMAC_SECRET, item.record_hash);
      if (item.hmac_signature !== recomputedHmac) {
        return {
          valid: false,
          brokenIndex: i,
          reason: `HMAC Signature Invalid: Block #${i} cryptographic signature failed authenticity check.`
        };
      }
    }

    return {
      valid: true,
      count: list.length,
      message: `Verified all ${list.length} blocks! Cryptographic chain intact & untampered.`
    };
  },

  // Tamper with record (Demo attack)
  tamperRecord(sequenceIndex) {
    if (simulatedAuditLog[sequenceIndex]) {
      simulatedAuditLog[sequenceIndex].details = {
        ...simulatedAuditLog[sequenceIndex].details,
        tampered_field: "EXPLOITED_BY_ATTACKER",
        exfiltrated_data: "MALICIOUS_INJECTION"
      };
      simulatedAuditLog[sequenceIndex].is_tampered = true;
      return true;
    }
    return false;
  },

  // Reset chain
  async resetChain() {
    simulatedAuditLog = [];
    return await initSimulatedAuditChain();
  },

  // Blue Canary Management
  getCanaries() {
    return [...simulatedCanaries];
  },

  addCanary(token) {
    const newCanary = {
      id: `canary-0${simulatedCanaries.length + 1}`,
      token,
      created: new Date().toISOString().replace('T', ' ').substring(0, 19),
      status: "Active / Monitored",
      triggers: 0
    };
    simulatedCanaries.push(newCanary);
    return newCanary;
  }
};
