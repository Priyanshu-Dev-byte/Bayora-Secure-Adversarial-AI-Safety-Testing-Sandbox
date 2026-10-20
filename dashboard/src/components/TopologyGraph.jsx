import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Server, 
  Database, 
  Terminal, 
  Lock, 
  ArrowRight, 
  Ban, 
  Key, 
  Filter, 
  Layers,
  Cpu
} from 'lucide-react';

export default function TopologyGraph({ sandboxMode }) {
  const [selectedNode, setSelectedNode] = useState('gateway');

  const nodes = {
    red: {
      name: "Red Sandbox",
      type: "Adversarial Engine",
      network: "net-red (Internal)",
      ip: "172.28.1.10",
      seccomp: "SCMP_ACT_ERRNO",
      caps: "ALL DROPPED",
      fs: "Read-Only + 64MB Tmpfs",
      desc: "Executes jailbreak generation, prompt injection, and adversarial fuzzing. No egress to internet or Blue."
    },
    blue: {
      name: "Blue Sandbox",
      type: "Defensive Engine",
      network: "net-blue (Internal)",
      ip: "172.28.2.10",
      seccomp: "SCMP_ACT_ERRNO",
      caps: "ALL DROPPED",
      fs: "Read-Only + 64MB Tmpfs",
      desc: "Maintains canary tokens, regex classifiers, and guardrail heuristics. Isolated completely from Red."
    },
    gateway: {
      name: "Policy Gateway",
      type: "Policy Enforcement Point",
      network: "net-red, net-blue, net-llm, net-control",
      ip: "172.28.0.2",
      seccomp: "Docker Default",
      caps: "NET_BIND_SERVICE",
      fs: "Read-Only + 64MB Tmpfs",
      desc: "Sole mediation nexus. Enforces allowlists, 100ms timing normalization padding, canary interception, rate limits."
    },
    llm: {
      name: "Client LLM",
      type: "Target Model Under Test",
      network: "net-llm (Internal)",
      ip: "172.28.3.10",
      seccomp: "SCMP_ACT_ERRNO",
      caps: "ALL DROPPED",
      fs: "Read-Only",
      desc: "Model under test. Accessible ONLY via Gateway. In isolated mode, maintains strict per-session KV caches."
    },
    control: {
      name: "Control Plane",
      type: "Central Orchestrator",
      network: "net-control",
      ip: "172.28.4.10",
      seccomp: "Strict Filter",
      caps: "NET_BIND_SERVICE",
      fs: "Read-Only + 64MB Tmpfs",
      desc: "Manages session lifecycle, capability tokens, and produces the append-only cryptographic hash chain."
    },
    postgres: {
      name: "PostgreSQL",
      type: "Tamper-Evident Store",
      network: "net-control",
      ip: "172.28.4.20",
      seccomp: "Default",
      caps: "Standard DB",
      fs: "Persistent Volume",
      desc: "Persists audit log records with prev_hash pointers and HMAC signatures."
    }
  };

  const activeNodeInfo = nodes[selectedNode] || nodes.gateway;

  return (
    <div className="glass-panel" style={{ padding: '24px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
        <div>
          <h2 className="heading-display" style={{ fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Layers size={20} color="var(--cyan-primary)" />
            Network Topology &amp; Isolation Invariants
          </h2>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-dim)', marginTop: '4px' }}>
            Micro-segmented Docker architecture enforcing the <strong>&quot;Zero-Trust No Direct Path&quot;</strong> rule.
          </p>
        </div>

        <div className="badge badge-cyan">
          <span>{sandboxMode === 'isolated' ? '4 ISOLATED NETWORKS ACTIVE' : 'VULNERABLE BRIDGE MODE'}</span>
        </div>
      </div>

      {/* Interactive Topology Visualizer */}
      <div className="topology-container">
        <div className="topology-grid">
          
          {/* Node 1: Red Sandbox */}
          <div 
            className={`node-box node-red ${selectedNode === 'red' ? 'node-selected' : ''}`}
            onClick={() => setSelectedNode('red')}
            style={{ cursor: 'pointer' }}
          >
            <div className="node-header">
              <span className="node-title" style={{ color: 'var(--red-accent)' }}>
                <Terminal size={17} />
                Red Sandbox
              </span>
              <span className="badge badge-red" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>net-red</span>
            </div>
            <div className="node-meta">172.28.1.10:8000</div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
              Adversarial attack generation
            </div>
          </div>

          {/* Node 2: Policy Gateway (Center Nexus) */}
          <div 
            className={`node-box node-gateway ${selectedNode === 'gateway' ? 'node-selected' : ''}`}
            onClick={() => setSelectedNode('gateway')}
            style={{ cursor: 'pointer', gridColumn: '2', gridRow: '1 / span 2' }}
          >
            <div className="node-header">
              <span className="node-title" style={{ color: 'var(--cyan-primary)' }}>
                <Filter size={18} />
                Policy Gateway (PEP)
              </span>
              <span className="badge badge-cyan" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>Multi-Homed</span>
            </div>
            <div className="node-meta">172.28.0.2:8000</div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-main)', marginTop: '4px', lineHeight: 1.4 }}>
              <strong>The ONLY Permitted Path:</strong>
              <ul style={{ paddingLeft: '18px', marginTop: '6px', color: 'var(--text-muted)', fontSize: '0.74rem' }}>
                <li>Allowlist access matrix</li>
                <li>Canary string interceptor</li>
                <li>100ms timing pad (side-channel mitigation)</li>
                <li>Rate limiter (60 req/min)</li>
              </ul>
            </div>
          </div>

          {/* Node 3: Blue Sandbox */}
          <div 
            className={`node-box node-blue ${selectedNode === 'blue' ? 'node-selected' : ''}`}
            onClick={() => setSelectedNode('blue')}
            style={{ cursor: 'pointer' }}
          >
            <div className="node-header">
              <span className="node-title" style={{ color: 'var(--blue-accent)' }}>
                <Lock size={17} />
                Blue Sandbox
              </span>
              <span className="badge badge-blue" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>net-blue</span>
            </div>
            <div className="node-meta">172.28.2.10:8000</div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
              Defense countermeasures &amp; secrets
            </div>
          </div>

          {/* Node 4: Client LLM */}
          <div 
            className={`node-box node-llm ${selectedNode === 'llm' ? 'node-selected' : ''}`}
            onClick={() => setSelectedNode('llm')}
            style={{ cursor: 'pointer', gridColumn: '1', gridRow: '2' }}
          >
            <div className="node-header">
              <span className="node-title" style={{ color: 'var(--purple-accent)' }}>
                <Cpu size={17} />
                Client LLM
              </span>
              <span className="badge badge-purple" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>net-llm</span>
            </div>
            <div className="node-meta">172.28.3.10:8000</div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
              Target model under evaluation
            </div>
          </div>

          {/* Node 5: Control Plane & Postgres */}
          <div 
            className="node-box"
            onClick={() => setSelectedNode('control')}
            style={{ cursor: 'pointer', gridColumn: '3', gridRow: '2', borderColor: 'rgba(16, 185, 129, 0.4)' }}
          >
            <div className="node-header">
              <span className="node-title" style={{ color: 'var(--emerald-accent)' }}>
                <Database size={17} />
                Control Plane &amp; DB
              </span>
              <span className="badge badge-emerald" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>net-control</span>
            </div>
            <div className="node-meta">172.28.4.10:8000 / 5432</div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
              Cryptographic hash-chain audit ledger
            </div>
          </div>

          {/* ISOLATION BARRIER: Red <-> Blue */}
          <div className="isolation-barrier">
            {sandboxMode === 'isolated' ? (
              <span className="barrier-text">
                <Ban size={16} />
                NO DIRECT PATH BETWEEN RED AND BLUE SANDBOXES (BLOCKED AT KERNEL &amp; DOCKER NETWORK)
              </span>
            ) : (
              <span className="barrier-text" style={{ color: 'var(--amber-accent)' }}>
                <ShieldAlert size={16} />
                WARNING: SHARED NAIVE SANDBOX DETECTED — CROSS-TALK LEAKS &amp; STATE CONTAMINATION POSSIBLE
              </span>
            )}
          </div>

        </div>
      </div>

      {/* Selected Node Details Card */}
      <div 
        style={{ 
          marginTop: '16px', 
          background: 'rgba(255, 255, 255, 0.02)', 
          border: '1px solid var(--border-subtle)', 
          borderRadius: 'var(--radius-md)',
          padding: '16px' 
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '0.95rem', fontWeight: 600 }}>{activeNodeInfo.name}</span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>({activeNodeInfo.type})</span>
          </div>
          <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--cyan-primary)' }}>
            IP: {activeNodeInfo.ip} | Network: {activeNodeInfo.network}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', fontSize: '0.78rem' }}>
          <div>
            <span style={{ color: 'var(--text-dim)', display: 'block' }}>Seccomp Profile:</span>
            <span className="mono" style={{ color: 'var(--emerald-accent)' }}>{activeNodeInfo.seccomp}</span>
          </div>
          <div>
            <span style={{ color: 'var(--text-dim)', display: 'block' }}>Linux Capabilities:</span>
            <span className="mono" style={{ color: 'var(--amber-accent)' }}>{activeNodeInfo.caps}</span>
          </div>
          <div>
            <span style={{ color: 'var(--text-dim)', display: 'block' }}>Filesystem Mode:</span>
            <span className="mono" style={{ color: 'var(--text-main)' }}>{activeNodeInfo.fs}</span>
          </div>
          <div>
            <span style={{ color: 'var(--text-dim)', display: 'block' }}>Enclave Function:</span>
            <span style={{ color: 'var(--text-muted)' }}>{activeNodeInfo.desc}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
