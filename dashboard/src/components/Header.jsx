import React from 'react';
import { 
  ShieldCheck, 
  Terminal, 
  Lock, 
  Cpu, 
  Layers, 
  Activity, 
  AlertTriangle,
  Radio
} from 'lucide-react';

export default function Header({ 
  activeTab, 
  setActiveTab, 
  sandboxMode, 
  setSandboxMode, 
  backendOnline, 
  uptime 
}) {
  return (
    <header className="top-nav">
      {/* Brand & Team ID */}
      <div className="brand-section">
        <div className="brand-logo-icon">
          <ShieldCheck size={22} />
        </div>
        <div>
          <div className="brand-title">BAYORA</div>
          <div className="brand-subtitle">Dark Panthers • Hack in Hills &apos;26</div>
        </div>
      </div>

      {/* Role / Perspective Switcher */}
      <div className="nav-tabs">
        <button
          id="btn-nav-admin"
          className={`nav-tab-btn ${activeTab === 'admin' ? 'active-admin' : ''}`}
          onClick={() => setActiveTab('admin')}
        >
          <Layers size={16} />
          <span>SecOps / Admin</span>
        </button>

        <button
          id="btn-nav-red"
          className={`nav-tab-btn ${activeTab === 'red' ? 'active-red' : ''}`}
          onClick={() => setActiveTab('red')}
        >
          <Terminal size={16} />
          <span>Red Team (Adversarial)</span>
        </button>

        <button
          id="btn-nav-blue"
          className={`nav-tab-btn ${activeTab === 'blue' ? 'active-blue' : ''}`}
          onClick={() => setActiveTab('blue')}
        >
          <Lock size={16} />
          <span>Blue Team (Defensive)</span>
        </button>
      </div>

      {/* Mode & Live Status */}
      <div className="nav-right-actions">
        {/* Isolated vs Naive Sandbox Toggle */}
        <button
          id="btn-toggle-mode"
          className="mode-toggle"
          onClick={() => setSandboxMode(sandboxMode === 'isolated' ? 'naive' : 'isolated')}
          title="Toggle between Bayora's Isolated Enclaves vs Naive Shared Sandbox"
        >
          {sandboxMode === 'isolated' ? (
            <>
              <span className="dot dot-green"></span>
              <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--cyan-primary)' }}>
                ISOLATED SANDBOX
              </span>
            </>
          ) : (
            <>
              <span className="dot dot-red"></span>
              <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--red-accent)' }}>
                NAIVE SHARED MODE
              </span>
            </>
          )}
        </button>

        {/* Live Backend Connection Indicator */}
        <div 
          className="badge" 
          style={{ 
            background: backendOnline ? 'rgba(16, 185, 129, 0.12)' : 'rgba(0, 245, 212, 0.12)',
            color: backendOnline ? 'var(--emerald-accent)' : 'var(--cyan-primary)',
            border: `1px solid ${backendOnline ? 'rgba(16, 185, 129, 0.3)' : 'rgba(0, 245, 212, 0.3)'}`
          }}
          title={backendOnline ? "Connected directly to FastAPI Backend on port 8000" : "Running high-fidelity browser cryptographic simulation"}
        >
          <Radio size={13} className="animate-pulse" />
          <span>{backendOnline ? 'LIVE API (8000)' : 'SECURE ENGINE'}</span>
        </div>
      </div>
    </header>
  );
}
