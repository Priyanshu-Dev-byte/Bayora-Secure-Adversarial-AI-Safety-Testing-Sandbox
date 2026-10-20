import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  AlertOctagon, 
  RefreshCw, 
  Bug, 
  Cpu, 
  FileCheck, 
  Key, 
  HardDrive, 
  Server,
  Lock,
  Layers
} from 'lucide-react';
import TopologyGraph from './TopologyGraph';
import { BayoraAPI } from '../api';

export default function AdminView({ sandboxMode }) {
  const [auditLog, setAuditLog] = useState([]);
  const [verificationResult, setVerificationResult] = useState(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [tamperedIndex, setTamperedIndex] = useState(null);

  // Load audit log on mount
  useEffect(() => {
    loadAuditTrail();
  }, []);

  const loadAuditTrail = async () => {
    const log = await BayoraAPI.getAuditLog();
    setAuditLog(log);
    setVerificationResult(null);
    setTamperedIndex(null);
  };

  const handleVerify = async () => {
    setIsVerifying(true);
    // Slight delay for realistic UX animation
    setTimeout(async () => {
      const result = await BayoraAPI.verifyChain(auditLog);
      setVerificationResult(result);
      if (!result.valid) {
        setTamperedIndex(result.brokenIndex);
      } else {
        setTamperedIndex(null);
      }
      setIsVerifying(false);
    }, 400);
  };

  const handleTamper = (index = 2) => {
    BayoraAPI.tamperRecord(index);
    const updated = [...auditLog];
    if (updated[index]) {
      updated[index] = {
        ...updated[index],
        details: { ...updated[index].details, tampered_field: "EXPLOITED_BY_ATTACKER" },
        is_tampered: true
      };
      setAuditLog(updated);
      setTamperedIndex(index);
      setVerificationResult({
        valid: false,
        brokenIndex: index,
        reason: `Cryptographic Alert: Tamper detected at Block #${index}! Hash mismatch: payload was mutated without valid HMAC key.`
      });
    }
  };

  const handleReset = async () => {
    const cleanLog = await BayoraAPI.resetChain();
    setAuditLog(cleanLog);
    setVerificationResult(null);
    setTamperedIndex(null);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* 1. Topology & Network Segmentation Section */}
      <TopologyGraph sandboxMode={sandboxMode} />

      {/* 2. Container Security Hardening Posture Grid */}
      <div className="grid-4">
        
        {/* Card 1: Read-Only Filesystem */}
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
            <HardDrive size={18} color="var(--cyan-primary)" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Root Filesystem</span>
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--emerald-accent)' }}>
            READ-ONLY (Enforced)
          </div>
          <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', marginTop: '4px' }}>
            Scratch memory restricted to ephemeral tmpfs (32MB). Zero disk persistence.
          </div>
        </div>

        {/* Card 2: Linux Capabilities */}
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
            <Key size={18} color="var(--purple-accent)" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Linux Capabilities</span>
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--purple-accent)' }}>
            CAP_DROP ALL
          </div>
          <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', marginTop: '4px' }}>
            Stripped of root escalation. Only NET_BIND_SERVICE kept for port binding.
          </div>
        </div>

        {/* Card 3: Seccomp Kernel Filtering */}
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
            <Lock size={18} color="var(--blue-accent)" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Seccomp Profile</span>
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--blue-accent)' }}>
            SCMP_ACT_ERRNO
          </div>
          <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', marginTop: '4px' }}>
            Blocks ptrace, sys_chroot, bpf, reboot, keyctl, and raw socket creation.
          </div>
        </div>

        {/* Card 4: Resource Cgroups Limits */}
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
            <Cpu size={18} color="var(--amber-accent)" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Cgroups Constraints</span>
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--amber-accent)' }}>
            256MB / 64 PIDs
          </div>
          <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', marginTop: '4px' }}>
            Prevents fork-bomb denial-of-service and memory starvation side channels.
          </div>
        </div>

      </div>

      {/* 3. Tamper-Evident Hash Chain Audit Log */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 className="heading-display" style={{ fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileCheck size={20} color="var(--cyan-primary)" />
              Cryptographic Hash-Chain Audit Ledger
            </h2>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-dim)', marginTop: '4px' }}>
              Every evaluation event, capability dispatch, and policy trigger is bound into an immutable 
              SHA-256 hash chain sealed with HMAC-SHA256 signatures.
            </p>
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              id="btn-verify-chain"
              className="btn btn-primary"
              onClick={handleVerify}
              disabled={isVerifying}
            >
              <ShieldCheck size={16} />
              <span>{isVerifying ? 'Verifying Proofs...' : 'Verify Chain Integrity'}</span>
            </button>

            <button
              id="btn-tamper-chain"
              className="btn btn-outline-red"
              onClick={() => handleTamper(2)}
              title="Simulate malicious tamper with Block #2 to demonstrate chain breakage"
            >
              <Bug size={16} />
              <span>Simulate Tamper (Block #2)</span>
            </button>

            <button
              id="btn-reset-chain"
              className="btn btn-secondary"
              onClick={handleReset}
              title="Reset chain back to pristine cryptographic state"
            >
              <RefreshCw size={15} />
            </button>
          </div>
        </div>

        {/* Verification Alert Banner */}
        {verificationResult && (
          <div 
            style={{ 
              marginBottom: '16px',
              padding: '14px 18px',
              borderRadius: 'var(--radius-md)',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              background: verificationResult.valid ? 'rgba(16, 185, 129, 0.12)' : 'rgba(255, 51, 102, 0.15)',
              border: `1px solid ${verificationResult.valid ? 'rgba(16, 185, 129, 0.4)' : 'rgba(255, 51, 102, 0.5)'}`,
            }}
          >
            {verificationResult.valid ? (
              <>
                <CheckCircle2 size={22} color="var(--emerald-accent)" />
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--emerald-accent)', fontSize: '0.9rem' }}>
                    CRYPTOGRAPHIC PROOF VERIFIED: CHAIN INTEGRITY 100% VALID
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                    {verificationResult.message}
                  </div>
                </div>
              </>
            ) : (
              <>
                <AlertOctagon size={24} color="var(--red-accent)" />
                <div>
                  <div style={{ fontWeight: 700, color: 'var(--red-accent)', fontSize: '0.92rem' }}>
                    TAMPER DETECTED: CRYPTOGRAPHIC HASH CHAIN COMPROMISED!
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#ffb3c1', marginTop: '2px' }}>
                    {verificationResult.reason}
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* Audit Log Table */}
        <div className="audit-table-wrapper">
          <table className="audit-table">
            <thead>
              <tr>
                <th>Seq #</th>
                <th>Timestamp</th>
                <th>Origin Team</th>
                <th>Event Type</th>
                <th>Prev Hash (Chain Link)</th>
                <th>Record Hash (SHA-256)</th>
                <th>HMAC Signature</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {auditLog.map((row, idx) => {
                const isTampered = row.is_tampered || (tamperedIndex === idx);
                return (
                  <tr key={row.sequence} className={isTampered ? 'tampered-row' : ''}>
                    <td className="mono" style={{ fontWeight: 600 }}>#{row.sequence}</td>
                    <td style={{ fontSize: '0.75rem' }}>{row.timestamp.substring(11, 19)}</td>
                    <td>
                      <span className={`badge badge-${row.team === 'red' ? 'red' : row.team === 'blue' ? 'blue' : 'purple'}`}>
                        {row.team}
                      </span>
                    </td>
                    <td className="mono" style={{ color: 'var(--text-main)', fontSize: '0.78rem' }}>
                      {row.event_type}
                    </td>
                    <td>
                      <span className="hash-pill" title={row.prev_hash}>
                        {row.prev_hash.substring(0, 10)}...{row.prev_hash.substring(58)}
                      </span>
                    </td>
                    <td>
                      <span className="hash-pill" title={row.record_hash} style={{ color: 'var(--cyan-primary)' }}>
                        {row.record_hash.substring(0, 10)}...{row.record_hash.substring(58)}
                      </span>
                    </td>
                    <td>
                      <span className="hash-pill" title={row.hmac_signature} style={{ color: 'var(--purple-accent)' }}>
                        {row.hmac_signature.substring(0, 8)}...
                      </span>
                    </td>
                    <td>
                      {isTampered ? (
                        <span className="badge badge-red" style={{ fontSize: '0.68rem' }}>
                          TAMPERED
                        </span>
                      ) : (
                        <span className="badge badge-emerald" style={{ fontSize: '0.68rem' }}>
                          VALID
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

      </div>

      {/* 4. Architectural Comparison: Naive vs Isolated Mode */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 className="heading-display" style={{ fontSize: '1.15rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Layers size={18} color="var(--cyan-primary)" />
          Bayora Architecture vs. Traditional Shared Sandboxes
        </h3>

        <div className="grid-2">
          
          {/* Box 1: Naive Approach */}
          <div style={{ background: 'rgba(255, 51, 102, 0.04)', border: '1px solid rgba(255, 51, 102, 0.25)', borderRadius: 'var(--radius-md)', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--red-accent)', fontWeight: 700, fontSize: '0.9rem', marginBottom: '8px' }}>
              <ShieldAlert size={18} />
              NAIVE SINGLE DOCKER CONTAINER
            </div>
            <ul style={{ paddingLeft: '20px', fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <li><strong>Shared Network Bridge:</strong> Red team can scan local ports and ARP tables to find Blue team processes.</li>
              <li><strong>KV-Cache Cross-Talk:</strong> Model under test shares attention key-value caches across multi-turn prompts.</li>
              <li><strong>Secret Exfiltration:</strong> Blue team detection regexes and canaries exist in shared memory or disk paths.</li>
              <li><strong>Timing Side-Channels:</strong> Red team can measure LLM token generation jitter to infer Blue defense activation.</li>
            </ul>
          </div>

          {/* Box 2: Bayora Secure Approach */}
          <div style={{ background: 'rgba(0, 245, 212, 0.04)', border: '1px solid rgba(0, 245, 212, 0.25)', borderRadius: 'var(--radius-md)', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--cyan-primary)', fontWeight: 700, fontSize: '0.9rem', marginBottom: '8px' }}>
              <ShieldCheck size={18} />
              BAYORA SECURE ISOLATED SANDBOX
            </div>
            <ul style={{ paddingLeft: '20px', fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <li><strong>Zero Direct Path:</strong> 4 segregated Linux bridge networks; Red &amp; Blue share zero network interfaces.</li>
              <li><strong>Session KV-Cache Partitioning:</strong> LLM runtime purges context state between evaluation passes.</li>
              <li><strong>Policy Gateway Interception:</strong> Every request is checked for canaries (`BLUE-SECRET-*`) and sanitized.</li>
              <li><strong>Timing Normalization:</strong> 100ms jitter padding neutralizes response latency profiling.</li>
            </ul>
          </div>

        </div>
      </div>

    </div>
  );
}
