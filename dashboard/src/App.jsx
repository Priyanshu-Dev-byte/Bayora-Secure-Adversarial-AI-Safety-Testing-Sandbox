import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import AdminView from './components/AdminView';
import RedTeamView from './components/RedTeamView';
import BlueTeamView from './components/BlueTeamView';
import { BayoraAPI, initSimulatedAuditChain } from './api';
import './App.css';

export default function App() {
  const [activeTab, setActiveTab] = useState('admin');
  const [sandboxMode, setSandboxMode] = useState('isolated');
  const [backendOnline, setBackendOnline] = useState(false);
  const [healthData, setHealthData] = useState(null);

  // Initialize and check health
  useEffect(() => {
    initSimulatedAuditChain();
    
    const checkConnection = async () => {
      const res = await BayoraAPI.checkHealth();
      setBackendOnline(res.online);
      setHealthData(res.data);
    };

    checkConnection();
    const interval = setInterval(checkConnection, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app-container">
      {/* Top Navigation */}
      <Header 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        sandboxMode={sandboxMode} 
        setSandboxMode={setSandboxMode}
        backendOnline={backendOnline}
        uptime={healthData?.uptime_seconds || 1420}
      />

      {/* Main View Port */}
      <main className="main-content">
        {activeTab === 'admin' && (
          <AdminView sandboxMode={sandboxMode} />
        )}

        {activeTab === 'red' && (
          <RedTeamView sandboxMode={sandboxMode} />
        )}

        {activeTab === 'blue' && (
          <BlueTeamView sandboxMode={sandboxMode} />
        )}
      </main>

      {/* Footer */}
      <footer style={{ 
        borderTop: '1px solid var(--border-subtle)', 
        padding: '16px 28px', 
        fontSize: '0.75rem', 
        color: 'var(--text-dim)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: 'rgba(8, 11, 18, 0.95)',
        marginTop: '32px'
      }}>
        <div>
          <strong style={{ color: 'var(--text-main)' }}>Bayora</strong> — Problem Statement 04: Securing Adversarial AI Safety Testing Infrastructure
        </div>
        <div style={{ display: 'flex', gap: '16px' }}>
          <span>Team: <strong style={{ color: 'var(--cyan-primary)' }}>Dark Panthers</strong></span>
          <span>Hack in Hills &apos;26 • Round 2 Prototype</span>
          <span className="mono">v0.1.0-secure</span>
        </div>
      </footer>
    </div>
  );
}
