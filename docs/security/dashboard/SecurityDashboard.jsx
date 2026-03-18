// Lattice Security View - React Dashboard Component
//
// Real-time security monitoring dashboard with alert feed,
// drift status, DNS threat monitoring, and sensitive access tracking.

import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, AlertTriangle, Activity, Lock, Eye, Search,
  Filter, Bell, CheckCircle, XCircle, Clock, Server,
  Network, Database, Globe, ChevronDown, RefreshCw, 
  Download, Settings, X, Info, Zap, ShieldAlert
} from 'lucide-react';

const API_BASE = '/api/security';

// Severity colors and labels
const SEVERITY_CONFIG = {
  CRITICAL: { color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/50', pulse: true },
  HIGH: { color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/50', pulse: false },
  MEDIUM: { color: 'text-yellow-500', bg: 'bg-yellow-500/10', border: 'border-yellow-500/50', pulse: false },
  LOW: { color: 'text-blue-500', bg: 'bg-blue-500/10', border: 'border-blue-500/50', pulse: false },
  INFO: { color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/50', pulse: false },
};

// Event type icons
const EVENT_ICONS = {
  SOCKET_CONNECT: Network,
  DNS_QUERY: Globe,
  SENSITIVE_PATH_ACCESS: Lock,
  BASELINE_DRIFT: AlertTriangle,
  DNS_TUNNEL: Zap,
};

function SecurityCard({ title, value, subtitle, icon: Icon, severity }) {
  const config = severity ? SEVERITY_CONFIG[severity] : SEVERITY_CONFIG.INFO;
  
  return (
    <div className={`
      p-6 rounded-xl border backdrop-blur-sm
      ${severity ? config.bg : 'bg-cyber-card'} 
      ${severity ? config.border : 'border-cyber-accent/20'}
      transition-all hover:scale-[1.02]
    `}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className={`
            p-3 rounded-lg
            ${severity ? config.bg : 'bg-cyber-accent/10'}
            border ${severity ? config.border : 'border-cyber-accent/20'}
          `}>
            <Icon size={20} className={severity ? config.color : 'text-cyber-accent'} />
          </div>
          <div>
            <div className="text-[10px] font-black uppercase tracking-widest text-cyber-accent/60 italic">
              {title}
            </div>
            <div className={`text-2xl font-black tracking-tighter ${severity ? config.color : 'text-white'}`}>
              {value}
            </div>
            <div className="text-[8px] font-bold uppercase tracking-tighter opacity-40 mt-1">
              {subtitle}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function AlertFeed({ events, onAcknowledge }) {
  const [filter, setFilter] = useState('ALL');
  
  const filteredEvents = filter === 'ALL' 
    ? events 
    : events.filter(e => e.severity === filter);

  return (
    <div className="bg-cyber-card border border-cyber-accent/20 rounded-xl overflow-hidden">
      <div className="p-4 border-b border-cyber-accent/10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert size={18} className="text-red-500" />
          <h2 className="text-sm font-black uppercase tracking-wider">Alert Feed</h2>
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-500 border border-red-500/30">
            {filteredEvents.length}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <select 
            className="bg-black/40 border border-cyber-accent/20 rounded px-2 py-1 text-[10px] text-cyber-accent"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <RefreshCw size={14} className="text-cyber-accent/40 cursor-pointer hover:text-cyber-accent" />
        </div>
      </div>
      
      <div className="max-h-[400px] overflow-y-auto">
        {filteredEvents.length === 0 ? (
          <div className="p-8 text-center text-cyber-accent/40 text-sm">
            <CheckCircle size={24} className="mx-auto mb-2 text-cyber-neon" />
            No security events to display
          </div>
        ) : (
          filteredEvents.map((event, idx) => {
            const config = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.INFO;
            const Icon = EVENT_ICONS[event.event_type] || Shield;
            
            return (
              <div 
                key={event.event_id || idx}
                className={`
                  p-4 border-b border-cyber-accent/5 
                  hover:bg-cyber-accent/5 transition-colors
                  ${config.pulse ? 'animate-pulse' : ''}
                `}
              >
                <div className="flex items-start gap-4">
                  <div className={`
                    p-2 rounded-lg ${config.bg}
                    border ${config.border}
                  `}>
                    <Icon size={16} className={config.color} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`
                        px-2 py-0.5 rounded text-[9px] font-black uppercase
                        ${config.bg} ${config.color} border ${config.border}
                      `}>
                        {event.severity}
                      </span>
                      <span className="text-[9px] text-cyber-accent/40 uppercase tracking-wider">
                        {event.event_type?.replace(/_/g, ' ')}
                      </span>
                    </div>
                    <div className="text-xs font-bold text-white/80 mb-1 truncate">
                      {event.pod_name || event.comm || 'Unknown Process'}
                    </div>
                    <div className="text-[10px] text-cyber-accent/60">
                      {event.namespace && <span>{event.namespace} / </span>}
                      {event.container_id && <span className="font-mono">{event.container_id.slice(0, 12)}...</span>}
                    </div>
                    {event.details && (
                      <div className="mt-2 p-2 bg-black/20 rounded text-[9px] font-mono text-cyber-accent/60">
                        {JSON.stringify(event.details, null, 0).slice(0, 200)}
                      </div>
                    )}
                  </div>
                  <div className="text-right">
                    <div className="text-[10px] text-cyber-accent/40">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </div>
                    <button
                      onClick={() => onAcknowledge?.(event.event_id)}
                      className="mt-2 text-[9px] px-2 py-1 rounded border border-cyber-accent/20 
                                 text-cyber-accent/60 hover:text-cyber-accent hover:border-cyber-accent/40
                                 transition-colors"
                    >
                      Ack
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

function DriftStatus({ driftData }) {
  return (
    <div className="bg-cyber-card border border-cyber-accent/20 rounded-xl overflow-hidden">
      <div className="p-4 border-b border-cyber-accent/10 flex items-center gap-3">
        <Activity size={18} className="text-orange-500" />
        <h2 className="text-sm font-black uppercase tracking-wider">Runtime Drift Status</h2>
      </div>
      
      <div className="p-4 space-y-4">
        {/* Overall Status */}
        <div className="flex items-center justify-between p-4 bg-black/20 rounded-lg border border-cyber-accent/10">
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full ${driftData?.total_drifts > 0 ? 'bg-orange-500 animate-pulse' : 'bg-cyber-neon'}`} />
            <span className="text-sm font-bold">
              {driftData?.total_drifts > 0 ? 'Drift Detected' : 'Baseline Normal'}
            </span>
          </div>
          <div className="text-2xl font-black text-cyber-neon">
            {driftData?.baseline_compliance || 100}%
            <span className="text-[10px] text-cyber-accent/40 ml-1">compliant</span>
          </div>
        </div>
        
        {/* Drift by Container */}
        <div className="space-y-2">
          <h3 className="text-[10px] font-black uppercase tracking-wider text-cyber-accent/60">
            Containers with Violations
          </h3>
          {driftData?.containers?.map((container, idx) => (
            <div key={idx} className="p-3 bg-black/20 rounded-lg border border-cyber-accent/10">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-white/80">{container.name}</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-orange-500/20 text-orange-500 border border-orange-500/30">
                  {container.violations} violations
                </span>
              </div>
              <div className="w-full bg-cyber-accent/10 rounded-full h-1.5">
                <div 
                  className="bg-orange-500 h-full rounded-full transition-all"
                  style={{ width: `${100 - (container.violations / container.accesses * 100)}%` }}
                />
              </div>
            </div>
          )) || (
            <div className="text-center py-4 text-cyber-accent/40 text-xs">
              No drift data available
            </div>
          )}
        </div>
        
        {/* Learning Mode Toggle */}
        <div className="flex items-center justify-between p-3 bg-black/20 rounded-lg border border-cyber-accent/10">
          <div>
            <div className="text-xs font-bold">Learning Mode</div>
            <div className="text-[10px] text-cyber-accent/60">
              Capture baseline behavior for new containers
            </div>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" className="sr-only peer" />
            <div className="w-11 h-6 bg-cyber-accent/20 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-cyber-accent after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyber-neon/20 peer-checked:border-cyber-neon"></div>
          </label>
        </div>
      </div>
    </div>
  );
}

function DNSPanel({ dnsThreats }) {
  return (
    <div className="bg-cyber-card border border-cyber-accent/20 rounded-xl overflow-hidden">
      <div className="p-4 border-b border-cyber-accent/10 flex items-center gap-3">
        <Globe size={18} className="text-purple-500" />
        <h2 className="text-sm font-black uppercase tracking-wider">DNS Threat Analysis</h2>
      </div>
      
      <div className="p-4 space-y-4">
        {/* Threat Indicators */}
        <div className="grid grid-cols-3 gap-3">
          <div className="p-3 bg-red-500/10 rounded-lg border border-red-500/20 text-center">
            <div className="text-xl font-black text-red-500">{dnsThreats?.high_entropy || 0}</div>
            <div className="text-[9px] text-red-500/60 uppercase">High Entropy</div>
          </div>
          <div className="p-3 bg-orange-500/10 rounded-lg border border-orange-500/20 text-center">
            <div className="text-xl font-black text-orange-500">{dnsThreats?.nxdomain_rate || 0}%</div>
            <div className="text-[9px] text-orange-500/60 uppercase">NXDOMAIN</div>
          </div>
          <div className="p-3 bg-purple-500/10 rounded-lg border border-purple-500/20 text-center">
            <div className="text-xl font-black text-purple-500">{dnsThreats?.suspicious_tlds || 0}</div>
            <div className="text-[9px] text-purple-500/60 uppercase">Suspicious TLD</div>
          </div>
        </div>
        
        {/* Recent DNS Events */}
        <div className="space-y-2">
          <h3 className="text-[10px] font-black uppercase tracking-wider text-cyber-accent/60">
            Recent Suspicious Queries
          </h3>
          {dnsThreats?.recent?.map((query, idx) => (
            <div key={idx} className="p-2 bg-black/20 rounded border border-cyber-accent/10 text-[10px] font-mono">
              <div className="flex items-center justify-between mb-1">
                <span className={`
                  px-1.5 py-0.5 rounded text-[8px] font-bold
                  ${query.threat === 'CRITICAL' ? 'bg-red-500/20 text-red-500' : 
                    query.threat === 'HIGH' ? 'bg-orange-500/20 text-orange-500' : 
                    'bg-yellow-500/20 text-yellow-500'}
                `}>
                  {query.threat}
                </span>
                <span className="text-cyber-accent/40">{query.timestamp}</span>
              </div>
              <div className="text-cyber-accent/80 truncate">{query.domain}</div>
            </div>
          )) || (
            <div className="text-center py-4 text-cyber-accent/40 text-xs">
              No suspicious DNS activity
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function SensitiveAccessPanel({ accessEvents }) {
  return (
    <div className="bg-cyber-card border border-cyber-accent/20 rounded-xl overflow-hidden">
      <div className="p-4 border-b border-cyber-accent/10 flex items-center gap-3">
        <Lock size={18} className="text-red-500" />
        <h2 className="text-sm font-black uppercase tracking-wider">Sensitive Path Access</h2>
      </div>
      
      <div className="p-4">
        {/* Protected Paths */}
        <div className="grid grid-cols-2 gap-2 mb-4">
          {[
            { path: '/etc/shadow', icon: Lock, critical: true },
            { path: '169.254.169.254', icon: Cloud, critical: true },
            { path: '/run/secrets/', icon: Key, critical: true },
            { path: 'admin.conf', icon: Shield, critical: false },
          ].map((item, idx) => (
            <div 
              key={idx}
              className={`
                p-2 rounded-lg border flex items-center gap-2
                ${item.critical ? 'bg-red-500/5 border-red-500/20' : 'bg-cyber-accent/5 border-cyber-accent/20'}
              `}
            >
              <item.icon size={12} className={item.critical ? 'text-red-500' : 'text-cyber-accent/60'} />
              <span className={`text-[9px] font-mono ${item.critical ? 'text-red-500/80' : 'text-cyber-accent/60'}`}>
                {item.path}
              </span>
            </div>
          ))}
        </div>
        
        {/* Access Events */}
        <div className="space-y-2">
          {accessEvents?.map((event, idx) => (
            <div key={idx} className="p-3 bg-black/20 rounded-lg border border-red-500/20">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono text-red-500/80">{event.path}</span>
                <span className="text-[9px] text-cyber-accent/40">{event.pod}</span>
              </div>
              <div className="text-[9px] text-cyber-accent/60">
                {event.namespace} / {event.timestamp}
              </div>
            </div>
          )) || (
            <div className="text-center py-4 text-cyber-accent/40 text-xs">
              No sensitive path access detected
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function SecurityDashboard() {
  const [activeTab, setActiveTab] = useState('alerts');
  const [events, setEvents] = useState([]);
  const [driftData, setDriftData] = useState(null);
  const [dnsThreats, setDnsThreats] = useState({});
  const [accessEvents, setAccessEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    total_alerts: 0,
    critical: 0,
    high: 0,
    medium: 0,
  });

  // Fetch security data
  const fetchSecurityData = useCallback(async () => {
    try {
      const token = localStorage.getItem('token');
      
      // Fetch events
      const eventsRes = await fetch(`${API_BASE}/events?limit=50`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const eventsData = await eventsRes.json();
      setEvents(eventsData.events || []);
      
      // Fetch drift data
      const driftRes = await fetch(`${API_BASE}/drift`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const driftData = await driftRes.json();
      setDriftData(driftData);
      
      // Fetch DNS threats
      const dnsRes = await fetch(`${API_BASE}/dns-threats`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const dnsData = await dnsRes.json();
      setDnsThreats(dnsData);
      
      // Fetch sensitive access
      const accessRes = await fetch(`${API_BASE}/sensitive-access`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const accessData = await accessRes.json();
      setAccessEvents(accessData.events || []);
      
      // Calculate stats
      const alerts = eventsData.events || [];
      setStats({
        total_alerts: alerts.length,
        critical: alerts.filter(e => e.severity === 'CRITICAL').length,
        high: alerts.filter(e => e.severity === 'HIGH').length,
        medium: alerts.filter(e => e.severity === 'MEDIUM').length,
      });
      
    } catch (err) {
      console.error('Failed to fetch security data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSecurityData();
    const interval = setInterval(fetchSecurityData, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, [fetchSecurityData]);

  const handleAcknowledge = async (eventId) => {
    try {
      const token = localStorage.getItem('token');
      await fetch(`${API_BASE}/alerts/${eventId}/acknowledge`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      fetchSecurityData();
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-cyber-accent animate-pulse">Loading security data...</div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Shield size={24} className="text-cyber-neon" />
          <h1 className="text-lg font-black uppercase tracking-wider">Security View</h1>
        </div>
        <div className="flex items-center gap-3">
          <button className="px-4 py-2 bg-cyber-neon/10 border border-cyber-neon/30 rounded-lg text-[10px] font-bold uppercase tracking-wider text-cyber-neon hover:bg-cyber-neon/20 transition-colors">
            <Settings size={12} className="inline mr-2" />
            Configure
          </button>
          <button 
            onClick={fetchSecurityData}
            className="px-4 py-2 bg-cyber-accent/10 border border-cyber-accent/30 rounded-lg text-[10px] font-bold uppercase tracking-wider text-cyber-accent hover:bg-cyber-accent/20 transition-colors"
          >
            <RefreshCw size={12} className="inline mr-2" />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4">
        <SecurityCard
          title="Total Alerts"
          value={stats.total_alerts}
          subtitle="Security Events"
          icon={Shield}
        />
        <SecurityCard
          title="Critical"
          value={stats.critical}
          subtitle="Immediate Action"
          icon={AlertTriangle}
          severity="CRITICAL"
        />
        <SecurityCard
          title="High"
          value={stats.high}
          subtitle="Requires Attention"
          icon={Zap}
          severity="HIGH"
        />
        <SecurityCard
          title="Medium"
          value={stats.medium}
          subtitle="Monitor"
          icon={Eye}
          severity="MEDIUM"
        />
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-3 gap-6">
        {/* Left Column - Alert Feed */}
        <div className="col-span-2">
          <AlertFeed events={events} onAcknowledge={handleAcknowledge} />
        </div>
        
        {/* Right Column */}
        <div className="space-y-6">
          <DriftStatus driftData={driftData} />
          <DNSPanel dnsThreats={dnsThreats} />
          <SensitiveAccessPanel accessEvents={accessEvents} />
        </div>
      </div>
    </div>
  );
}
