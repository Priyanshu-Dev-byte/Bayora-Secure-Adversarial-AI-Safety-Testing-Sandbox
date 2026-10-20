import React, { useState } from 'react';
import { 
  Lock, 
  ShieldCheck, 
  Key, 
  Plus, 
  CheckCircle2, 
  AlertTriangle, 
  Cpu, 
  Clock, 
  Activity, 
  Sliders, 
  Zap,
  Radio
} from 'lucide-react';
import { BayoraAPI } from '../api';

export default function BlueTeamView({ sandboxMode }) {
  const [canaries, setCanaries] = useState(BayoraAPI.getCanaries());
  const [newCanaryInput, setNewCanaryInput] = useState('');
  
  // Guardrail policy toggles
  const [policies, setPolicies] = useState({
    canaryFilter: true,
    timingPad: true,
    kvCachePurge: true,
    rateLimiting: true
  });

  const [testResults, setTestResults] = useState(null);
  const [isRunningSuite, setIsRunningSuite] = useState(false);

  const handleTogglePolicy = (key) => {
    setPolicies(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleAddCanary = () => {
    if (!newCanaryInput.trim()) return;
    const token = newCanaryInput.trim().toUpperCase();
    const created = BayoraAPI.addCanary(token);
    setCanaries(BayoraAPI.getCanaries());
    setNewCanaryInput('');
    BayoraAPI.appendAuditEvent("blue.canary_registered", "blue", { token: created.token });
  };

  const handleRunDefenseSuite = () => {
    setIsRunningSuite(true);
    setTimeout(async () => {
      const suite = [
        { test: "Canary Exfiltration (BLUE-SECRET-* Pattern)", passed: policies.canaryFilter, latency: "102ms" },
        { test: "Side-Channel Timing Profiling (100ms normalization)", passed: policies.timingPad, latency: "105ms" },
        { test: "KV-Cache Cross-Session State Poisoning", passed: policies.kvCachePurge, latency: "110ms" },
        { test: "Cross-Container Direct ARP & Socket Probe", passed: sandboxMode === 'isolated', latency: "4ms" },
        { test: "Rate-Burst DoS Flood (60 req/min limit)", passed: policies.rateLimiting, latency: "98ms" },
      ];

      setTestResults(suite);
      setIsRunningSuite(false);

      await BayoraAPI.appendAuditEvent("blue.defense_suite_evaluated", "blue", {
        passed: suite.filter(s => s.passed).length,
        total: suite.length
      });
    }, 500);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Header */}
      <div className="glass-panel" style={{ padding: '24px', borderColor: 'rgba(56, 189, 248, 0.3)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 className="heading-display" style={{ fontSize: '1.25rem', color: 'var(--blue-accent)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Lock size={22} />
              Blue Team Defensive Countermeasures &amp; Canary Vault
            </h2>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-dim)', marginTop: '4px' }}>
              Manage defensive policies, register tripwire canaries, and monitor side-channel mitigation filters.
            </p>
          </div>

          <div className="badge badge-blue">
            <Radio size={14} className="animate-pulse" />
            <span>SANDBOX: NET-BLUE (172.28.2.10)</span>
          </div>
        </div>
      </div>

      <div className="grid-2">
        
        {/* Left: Canary Token Sentinel */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Key size={18} color="var(--blue-accent)" />
              Tripwire Canary Tokens
            </h3>
            <span className="badge badge-cyan">{canaries.length} Deployed</span>
          </div>

          <p style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginBottom: '14px' }}>
            Canary tokens are embedded into internal test prompts. If the Gateway detects any Canary token in Red team outputs, an exfiltration alert is immediately logged.
          </p>

          {/* Canary List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginBottom: '18px' }}>
            {canaries.map((canary) => (
              <div 
                key={canary.id}
                style={{ 
                  background: 'rgba(255, 255, 255, 0.02)', 
                  border: '1px solid var(--border-subtle)', 
                  borderRadius: 'var(--radius-md)',
                  padding: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between'
                }}
              >
                <div>
                  <div className="mono" style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--cyan-primary)' }}>
                    {canary.token}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>
                    Created: {canary.created}
                  </div>
                </div>

                <div className="badge badge-emerald" style={{ fontSize: '0.7rem' }}>
                  <ShieldCheck size={12} />
                  <span>{canary.status}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Add Canary Form */}
          <div style={{ display: 'flex', gap: '8px' }}>
            <input 
              type="text" 
              placeholder="e.g. BLUE-SECRET-PROD-998"
              value={newCanaryInput}
              onChange={(e) => setNewCanaryInput(e.target.value)}
              className="mono"
              style={{ fontSize: '0.82rem' }}
            />
            <button 
              id="btn-add-canary"
              className="btn btn-primary"
              onClick={handleAddCanary}
              style={{ whiteSpace: 'nowrap' }}
            >
              <Plus size={15} />
              <span>Deploy Canary</span>
            </button>
          </div>

        </div>

        {/* Right: Policy & Guardrails Matrix */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Sliders size={18} color="var(--cyan-primary)" />
            Active Gateway Policy Filters
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '20px' }}>
            
            {/* Policy 1 */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
              <div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>Canary Exfiltration Filter</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Intersects LLM completions matching regex patterns `BLUE-SECRET-*`</div>
              </div>
              <button 
                className={`btn btn-${policies.canaryFilter ? 'outline-cyan' : 'secondary'}`} 
                style={{ padding: '4px 12px', fontSize: '0.75rem' }}
                onClick={() => handleTogglePolicy('canaryFilter')}
              >
                {policies.canaryFilter ? 'ENABLED' : 'DISABLED'}
              </button>
            </div>

            {/* Policy 2 */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
              <div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>100ms Timing Normalization Pad</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Injects synthetic delay jitter to mask side-channel latency profiling</div>
              </div>
              <button 
                className={`btn btn-${policies.timingPad ? 'outline-cyan' : 'secondary'}`} 
                style={{ padding: '4px 12px', fontSize: '0.75rem' }}
                onClick={() => handleTogglePolicy('timingPad')}
              >
                {policies.timingPad ? 'ENABLED' : 'DISABLED'}
              </button>
            </div>

            {/* Policy 3 */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
              <div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>Session KV-Cache Isolation Purge</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Zeroes GPU/CPU attention caches across evaluation requests</div>
              </div>
              <button 
                className={`btn btn-${policies.kvCachePurge ? 'outline-cyan' : 'secondary'}`} 
                style={{ padding: '4px 12px', fontSize: '0.75rem' }}
                onClick={() => handleTogglePolicy('kvCachePurge')}
              >
                {policies.kvCachePurge ? 'ENABLED' : 'DISABLED'}
              </button>
            </div>

            {/* Policy 4 */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
              <div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>Adversarial Rate Limiter</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Enforces maximum 60 requests/minute per evaluation key</div>
              </div>
              <button 
                className={`btn btn-${policies.rateLimiting ? 'outline-cyan' : 'secondary'}`} 
                style={{ padding: '4px 12px', fontSize: '0.75rem' }}
                onClick={() => handleTogglePolicy('rateLimiting')}
              >
                {policies.rateLimiting ? 'ENABLED' : 'DISABLED'}
              </button>
            </div>

          </div>

          {/* Test Runner */}
          <button 
            id="btn-run-defense-suite"
            className="btn btn-primary"
            style={{ width: '100%' }}
            onClick={handleRunDefenseSuite}
            disabled={isRunningSuite}
          >
            <Zap size={16} />
            <span>{isRunningSuite ? 'Executing Verification...' : 'Run Defense Guardrail Test Suite'}</span>
          </button>

          {/* Suite Results */}
          {testResults && (
            <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {testResults.map((t, idx) => (
                <div 
                  key={idx} 
                  style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-sm)',
                    background: t.passed ? 'rgba(16, 185, 129, 0.08)' : 'rgba(255, 51, 102, 0.08)',
                    border: `1px solid ${t.passed ? 'rgba(16, 185, 129, 0.25)' : 'rgba(255, 51, 102, 0.25)'}`,
                    fontSize: '0.78rem'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {t.passed ? (
                      <CheckCircle2 size={15} color="var(--emerald-accent)" />
                    ) : (
                      <AlertTriangle size={15} color="var(--red-accent)" />
                    )}
                    <span>{t.test}</span>
                  </div>
                  <div className="mono" style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>
                    {t.latency}
                  </div>
                </div>
              ))}
            </div>
          )}

        </div>

      </div>

    </div>
  );
}
