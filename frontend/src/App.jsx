import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Lock, Server, Shield, Activity, Plus, LogOut, Search, 
  Cpu, Database, Globe, AlertTriangle, CheckCircle2,
  Terminal as TerminalIcon, Menu, X, Edit, Network, Layers, ShieldAlert, RefreshCw
} from 'lucide-react';
import ReactFlow, { Background, Controls } from 'reactflow';
import 'reactflow/dist/style.css';

const API_BASE = "/api";

function DashboardCard({ icon, title, value, subtitle, alert = false, onClick }) {
  return (
    <div 
      onClick={onClick}
      className={`
      bg-cyber-card border p-6 rounded-xl flex items-center gap-6 transition-all hover:scale-[1.02] cursor-default
      ${alert ? 'border-red-500/50 bg-red-500/5 shadow-[0_0_20px_rgba(239,68,68,0.1)]' : 'border-cyber-accent/20 shadow-[0_0_20px_rgba(112,0,255,0.05)]'}
      ${onClick ? 'cursor-pointer hover:border-cyber-neon/50' : ''}
    `}>
      <div className={`p-4 rounded-xl ${alert ? 'bg-red-500/10' : 'bg-cyber-accent/10 border border-cyber-accent/20'}`}>
        {React.cloneElement(icon, { size: 24 })}
      </div>
      <div>
        <div className="text-[10px] font-black uppercase tracking-widest text-cyber-accent/60 italic leading-none mb-1">{title}</div>
        <div className={`text-3xl font-black tracking-tighter ${alert ? 'text-red-500' : 'text-white'}`}>{value}</div>
        <div className="text-[8px] font-bold uppercase tracking-tighter opacity-40 mt-1">{subtitle}</div>
      </div>
    </div>
  );
}

function StatusBadge({ status }) {
  const isRunning = status === 'Running' || status === 'Active' || status === 'Ready';
  return (
    <div className={`flex items-center gap-2 px-2 py-1 rounded border text-[9px] font-black uppercase tracking-widest ${
      isRunning ? 'bg-cyber-neon/10 text-cyber-neon border-cyber-neon/30' : 'bg-red-500/10 text-red-400 border-red-500/30'
    }`}>
      <div className={`w-1.5 h-1.5 rounded-full ${isRunning ? 'bg-cyber-neon animate-pulse' : 'bg-red-500'}`} />
      {status}
    </div>
  );
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [topology, setTopology] = useState({ nodes: [], edges: [] });
  const [flows, setFlows] = useState([]);
  const [loginForm, setLoginForm] = useState({ username: 'admin', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('Overview');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [securityData, setSecurityData] = useState({ 
    events: [], 
    alerts: [], 
    drift: null, 
    dns: {}, 
    sensitive: [],
    baseline: { learning_enabled: false, status: 'inactive', paths_captured: 0, processes_captured: 0 }
  });
  const [selectedSecurityDetail, setSelectedSecurityDetail] = useState(null);

  useEffect(() => {
    if (token) {
      fetchTopology();
      fetchFlows();
      fetchSecurityData();
      const interval = setInterval(() => {
        fetchTopology();
        fetchFlows();
      }, 5000);
      const securityInterval = setInterval(fetchSecurityData, 3000);
      return () => {
        clearInterval(interval);
        clearInterval(securityInterval);
      };
    }
  }, [token]);

  const fetchSecurityData = async () => {
    try {
      const headers = { headers: { Authorization: `Bearer ${token}` } };
      const [eventsRes, alertsRes, driftRes, dnsRes, sensitiveRes, baselineRes] = await Promise.all([
        axios.get(`${API_BASE}/security/events`, headers),
        axios.get(`${API_BASE}/security/alerts`, headers),
        axios.get(`${API_BASE}/security/drift`, headers),
        axios.get(`${API_BASE}/security/dns-threats`, headers),
        axios.get(`${API_BASE}/security/sensitive-access`, headers),
        axios.get(`${API_BASE}/security/baseline`, headers),
      ]);
      setSecurityData(prev => ({
        ...prev,
        events: eventsRes.data.events || [],
        alerts: alertsRes.data.alerts || [],
        drift: driftRes.data,
        dns: dnsRes.data,
        sensitive: sensitiveRes.data.events || [],
        baseline: baselineRes.data || prev.baseline,
      }));
    } catch (err) {
      console.error('Failed to fetch security data:', err);
    }
  };

  const toggleBaselineLearning = async () => {
    try {
      const newState = !securityData.baseline.learning_enabled;
      await axios.put(
        `${API_BASE}/security/baseline`,
        { learning_enabled: newState },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setSecurityData(prev => ({
        ...prev,
        baseline: {
          ...prev.baseline,
          learning_enabled: newState,
          status: newState ? 'learning' : 'inactive',
          learning_start_time: newState ? new Date().toISOString() : null,
        }
      }));
    } catch (err) {
      console.error('Failed to toggle baseline learning:', err);
    }
  };

  const fetchTopology = async () => {
    try {
      const resp = await axios.get(`${API_BASE}/topology`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const nodesByNs = {};
      resp.data.nodes.forEach(n => {
        const ns = n.namespace || 'default';
        if (!nodesByNs[ns]) nodesByNs[ns] = [];
        nodesByNs[ns].push(n);
      });
      
      const nsActivity = {};
      (resp.data.links || []).forEach(l => {
        const srcNs = resp.data.nodes.find(n => n.id === l.source)?.namespace || 'default';
        nsActivity[srcNs] = (nsActivity[srcNs] || 0) + 1;
      });
      
      const nsOrder = Object.keys(nodesByNs).sort((a, b) => (nsActivity[b] || 0) - (nsActivity[a] || 0));
      
      const podWidth = 180;
      const podHeight = 100;
      const podGapX = 50;
      const podGapY = 40;
      const cols = 5;
      const startX = 50;
      const startY = 50;
      const nsGapY = 60;
      
      const rfNodes = [];
      let currentY = startY;
      
      nsOrder.forEach((ns) => {
        const nsPods = nodesByNs[ns];
        const rowsInNs = Math.ceil(nsPods.length / cols);
        const nsWidth = Math.min(nsPods.length, cols) * (podWidth + podGapX) - podGapX + 20;
        const nsHeight = rowsInNs * (podHeight + podGapY) - podGapY + 30;
        
        rfNodes.push({
          id: `ns-bg-${ns}`,
          type: 'group',
          data: { label: '' },
          position: { x: startX - 10 + 60, y: currentY - 10 },
          draggable: false,
          selectable: false,
          style: { 
            width: nsWidth - 60,
            height: nsHeight,
            background: 'rgba(18, 18, 22, 0.6)',
            border: '1px solid rgba(0, 255, 157, 0.2)',
            borderRadius: '16px',
          }
        });
        
        rfNodes.push({
          id: `ns-label-${ns}`,
          type: 'default',
          data: { 
            label: (
              <div style={{ 
                writingMode: 'vertical-rl', 
                textOrientation: 'mixed',
                transform: 'rotate(180deg)',
                color: 'rgba(0, 255, 157, 0.8)',
                fontSize: '16px',
                fontWeight: '900',
                textTransform: 'uppercase',
                letterSpacing: '0.2em',
                padding: '16px 8px',
                background: 'rgba(0, 0, 0, 0.8)',
                border: '1px solid rgba(0, 255, 157, 0.3)',
                borderRadius: '8px',
              }}>
                {ns}
              </div>
            )
          },
          position: { x: startX - 10, y: currentY + nsHeight / 2 - 60 },
          draggable: false,
          selectable: false,
          style: { 
            background: 'transparent',
            border: 'none',
            padding: 0,
          }
        });
        
        nsPods.forEach((n, i) => {
          const row = Math.floor(i / cols);
          const col = i % cols;
          const restartCount = n.metrics?.restart_count || 0;
          const isHighRestart = restartCount > 0;
          const restartIntensity = Math.min(restartCount / 10, 1);
          const borderColor = isHighRestart 
            ? `rgba(255, ${Math.round(60 - restartIntensity * 50)}, ${Math.round(60 - restartIntensity * 50)}, 0.7)`
            : 'rgba(112, 0, 255, 0.4)';
          const shadowColor = isHighRestart 
            ? `rgba(255, ${Math.round(40 - restartIntensity * 40)}, ${Math.round(40 - restartIntensity * 40)}, 0.3)`
            : 'rgba(112, 0, 255, 0.15)';
          rfNodes.push({
            id: n.id,
            type: n.type,
            name: n.name,
            status: n.status,
            metrics: n.metrics,
            node: n.node,
            namespace: n.namespace,
            ip: n.ip,
            data: { 
              label: (
                <div className="flex flex-col items-center gap-1 p-2">
                  <span className="text-[8px] font-black uppercase tracking-tight text-cyber-accent/60">{ns}</span>
                  <span className="text-[10px] font-black uppercase tracking-tight">{n.name}</span>
                  {isHighRestart && (
                    <span className="text-[7px] font-bold px-1 py-0.5 rounded border border-red-500/50 text-red-400 bg-red-500/10">
                      {restartCount} RESTART{restartCount > 1 ? 'S' : ''}
                    </span>
                  )}
                  <span className={`text-[7px] font-bold px-1.5 py-0.5 rounded border ${
                    n.type === 'pod' ? 'border-cyan-400/30 text-cyan-400 bg-cyan-400/5' : 
                    n.type === 'service' ? 'border-purple-500/30 text-purple-400 bg-purple-500/5' :
                    'border-white/20 text-white bg-white/5'
                  }`}>
                    {n.type.toUpperCase()}
                  </span>
                </div>
              ) 
            },
            position: { x: startX + 50 + col * (podWidth + podGapX), y: currentY + row * (podHeight + podGapY) },
            style: { 
              background: '#121216',
              color: '#e2e2e7',
              border: `2px solid ${borderColor}`,
              borderRadius: '12px',
              width: podWidth,
              boxShadow: `0 0 15px ${shadowColor}`,
            }
          });
        });
        
        currentY += rowsInNs * (podHeight + podGapY) + nsGapY;
      });
      const rfEdges = resp.data.links.map((l, i) => ({
        id: `e-${i}`,
        source: l.source,
        target: l.target,
        animated: true,
        style: { stroke: 'rgba(0, 255, 157, 0.5)', strokeWidth: 2 },
        type: 'smoothstep'
      }));
      setTopology({ nodes: rfNodes, edges: rfEdges });
    } catch (e) {
      if (e.response?.status === 401) handleLogout();
    }
  };

  const fetchFlows = async () => {
    try {
      const resp = await axios.get(`${API_BASE}/flows`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setFlows(resp.data);
    } catch (e) {}
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    const params = new URLSearchParams();
    params.append('username', loginForm.username);
    params.append('password', loginForm.password);
    
    try {
      const resp = await axios.post(`${API_BASE}/token`, params);
      const newToken = resp.data.access_token;
      localStorage.setItem('token', newToken);
      setToken(newToken);
    } catch (e) {
      setError('AUTHENTICATION_FAILED: ACCESS_DENIED');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
  };

  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-cyber-dark cyber-grid relative overflow-hidden">
        <div className="scanline" />
        <div className="max-w-md w-full z-10 mx-4">
          <div className="bg-cyber-card/80 backdrop-blur-md border border-cyber-accent/30 p-10 rounded-2xl glow-border">
            <div className="flex justify-center mb-8">
              <div className="p-6 bg-cyber-accent/10 rounded-2xl border border-cyber-neon/30 shadow-[0_0_30px_rgba(0,255,157,0.1)]">
                <Network size={56} className="text-cyber-neon" />
              </div>
            </div>
            <h2 className="text-3xl font-black text-center mb-2 tracking-[0.4em] text-white uppercase italic">
              LATTICE_LINK
            </h2>
            <p className="text-[10px] text-center mb-10 text-cyber-neon font-black tracking-[0.3em] opacity-70">
              CLUSTER_VISUALIZATION_PROTOCOLS // V1.0.2
            </p>
            
            <form onSubmit={handleLogin} className="space-y-6">
              <div className="space-y-2">
                <label className="text-[10px] uppercase tracking-[0.3em] text-cyber-accent font-black italic ml-1">Administrator_ID</label>
                <input 
                  type="text" 
                  className="w-full bg-black/60 border border-cyber-accent/30 p-4 rounded-xl focus:border-cyber-neon outline-none text-cyber-neon transition-all placeholder-cyber-accent/20 font-mono text-sm"
                  value={loginForm.username}
                  onChange={e => setLoginForm({...loginForm, username: e.target.value})}
                />
              </div>

              <div className="space-y-2">
                <div className="flex justify-between items-center px-1">
                  <label className="text-[10px] uppercase tracking-[0.3em] text-cyber-accent font-black italic">Security_Key</label>
                  <Lock size={12} className="text-cyber-accent/40" />
                </div>
                <input 
                  type="password" 
                  placeholder="••••••••"
                  className="w-full bg-black/60 border border-cyber-accent/30 p-4 rounded-xl focus:border-cyber-neon outline-none text-cyber-neon transition-all placeholder-cyber-accent/20 font-mono text-sm"
                  value={loginForm.password}
                  onChange={e => setLoginForm({...loginForm, password: e.target.value})}
                />
              </div>

              {error && (
                <div className="bg-red-900/20 border border-red-500/50 p-4 rounded-xl text-red-400 text-[10px] font-black flex items-center gap-3 animate-pulse">
                  <AlertTriangle size={16} /> {error}
                </div>
              )}

              <button 
                disabled={loading}
                className="w-full bg-cyber-accent hover:bg-cyber-neon hover:text-black text-white font-black py-5 rounded-xl transition-all tracking-[0.3em] group relative overflow-hidden shadow-lg shadow-cyber-accent/20"
              >
                <span className="relative z-10">{loading ? 'ESTABLISHING_UPLINK...' : 'INITIALIZE_SESSION'}</span>
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:animate-shimmer" />
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  const pods = topology.nodes.filter(n => n.type === 'pod');
  const podsByNamespace = pods.reduce((acc, pod) => {
    const ns = pod.namespace || 'default';
    if (!acc[ns]) acc[ns] = [];
    acc[ns].push(pod);
    return acc;
  }, {});

  return (
    <div className="h-screen bg-cyber-dark flex flex-col relative overflow-hidden font-mono">
      <div className="scanline" />
      
      <header className="h-16 border-b border-cyber-accent/20 bg-cyber-card/90 backdrop-blur-md flex items-center justify-between px-8 z-50 shadow-2xl">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3 cursor-pointer group" onClick={() => setSidebarOpen(!sidebarOpen)}>
            <div className="p-2 bg-cyber-accent/10 border border-cyber-neon/30 rounded-lg group-hover:scale-110 transition-transform shadow-[0_0_15px_rgba(0,255,157,0.1)]">
              <Layers size={24} className="text-cyber-neon" />
            </div>
            <div className="flex flex-col">
              <span className="text-lg font-black tracking-tighter text-white uppercase italic group-hover:text-cyber-neon transition-colors">Lattice_Grid</span>
              <span className="text-[9px] text-cyber-accent/60 font-black uppercase tracking-[0.2em]">Observable_System_V1</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-8">
          <div className="flex items-center gap-3 px-4 py-2 bg-black/40 border border-cyber-accent/20 rounded-xl">
            <div className="flex flex-col items-end">
              <span className="text-[10px] text-cyber-neon font-black uppercase tracking-widest">System_Status: Optimal</span>
              <span className="text-[9px] text-cyber-accent/40 font-black">Cluster_Nodes: {topology.nodes.filter(n => n.type === 'node').length}</span>
            </div>
            <div className="w-2.5 h-2.5 bg-cyber-neon rounded-full animate-pulse shadow-[0_0_10px_rgba(0,255,157,0.8)]" />
          </div>
          <button 
            onClick={handleLogout}
            className="flex items-center gap-2 px-5 py-2.5 bg-cyber-card border border-cyber-accent/30 hover:border-red-500 hover:text-red-500 rounded-xl text-[10px] font-black tracking-[0.2em] transition-all uppercase"
          >
            <LogOut size={14} /> Terminate_Link
          </button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <aside className={`${sidebarOpen ? 'w-64' : 'w-20'} border-r border-cyber-accent/10 bg-cyber-card/40 backdrop-blur-xl transition-all duration-300 flex flex-col py-8 gap-4 z-40 overflow-hidden`}>
           <NavItem icon={<Activity size={22}/>} active={activeTab === 'Overview'} onClick={() => setActiveTab('Overview')} label="Overview" open={sidebarOpen} />
           <NavItem icon={<Server size={22}/>} active={activeTab === 'Nodes'} onClick={() => setActiveTab('Nodes')} label="Compute_Nodes" open={sidebarOpen} />
           <NavItem icon={<Layers size={22}/>} active={activeTab === 'Pods'} onClick={() => setActiveTab('Pods')} label="Active_Pods" open={sidebarOpen} />
           <NavItem icon={<Globe size={22}/>} active={activeTab === 'Topology'} onClick={() => setActiveTab('Topology')} label="Grid_Map" open={sidebarOpen} />
           <NavItem icon={<Cpu size={22}/>} active={activeTab === 'Flows'} onClick={() => setActiveTab('Flows')} label="Flow_Matrix" open={sidebarOpen} />
           <NavItem icon={<ShieldAlert size={22}/>} active={activeTab === 'Security'} onClick={() => setActiveTab('Security')} label="Security_View" open={sidebarOpen} />
           <div className="mt-auto px-6 opacity-30 italic flex items-center gap-3">
              <TerminalIcon size={16} />
              {sidebarOpen && <span className="text-[9px] font-black uppercase tracking-widest">Session_Active: root</span>}
           </div>
        </aside>

        <main className="flex-1 cyber-grid relative overflow-y-auto p-10">
          <div className="max-w-7xl mx-auto space-y-10">
            
            {activeTab === 'Overview' && (
              <>
                <div className="flex flex-col gap-2 border-l-4 border-cyber-neon pl-6 mb-10">
                   <h1 className="text-4xl font-black text-white uppercase italic tracking-tighter">Cluster_Diagnostics</h1>
                   <p className="text-xs text-cyber-accent font-black uppercase tracking-[0.3em] opacity-60 italic">Real-time health and infrastructure metrics</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                  <DashboardCard 
                    icon={<Server />}
                    title="Compute_Nodes"
                    value={topology.nodes.filter(n => n.type === 'node').length}
                    subtitle="PHYSICAL_INFRASTRUCTURE"
                    onClick={() => setActiveTab('Nodes')}
                  />
                  <DashboardCard 
                    icon={<Layers />}
                    title="Active_Pods"
                    value={pods.length}
                    subtitle="VIRTUALIZED_CONTAINERS"
                    onClick={() => setActiveTab('Pods')}
                  />
                  <DashboardCard 
                    icon={<Globe />}
                    title="Traffic_Flows"
                    value={flows.length}
                    subtitle="INTER_NODE_COMMUNICATION"
                    onClick={() => setActiveTab('Flows')}
                  />
                  <DashboardCard 
                    icon={<Shield />}
                    title="Security_Posture"
                    value="Optimal"
                    subtitle="ENFORCEMENT_PROTOCOL"
                  />
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-10 mt-12">
                   <div className="lg:col-span-2 bg-cyber-card/80 border border-cyber-accent/20 rounded-2xl p-8 backdrop-blur-sm shadow-2xl">
                      <div className="flex justify-between items-center mb-8 border-b border-cyber-accent/10 pb-4">
                         <h3 className="text-sm font-black uppercase tracking-[0.3em] text-white italic">Recent_Activity_Stream</h3>
                         <span className="text-[8px] text-cyber-neon font-black uppercase tracking-widest animate-pulse">Monitoring...</span>
                      </div>
                      <div className="space-y-4 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
                         {flows.slice(0, 10).map((flow, i) => (
                           <div key={i} className="flex items-center justify-between p-4 bg-black/40 border border-cyber-accent/10 rounded-xl hover:border-cyber-neon/40 transition-all group">
                              <div className="flex items-center gap-4">
                                 <div className="p-2 bg-cyber-neon/5 border border-cyber-neon/20 rounded text-cyber-neon">
                                    <Activity size={14} />
                                 </div>
                                 <div className="flex flex-col">
                                    <span className="text-[10px] font-black text-white group-hover:text-cyber-neon transition-colors uppercase italic">{flow.source}</span>
                                    <span className="text-[8px] text-cyber-accent uppercase font-bold tracking-tighter">Connection established to {flow.dest}</span>
                                 </div>
                              </div>
                              <div className="text-right">
                                 <div className="text-[9px] font-mono text-cyber-accent">:{flow.port}</div>
                                 <div className="text-[7px] font-black text-cyber-accent/40 uppercase">Success_200</div>
                              </div>
                           </div>
                         ))}
                      </div>
                   </div>

                   <div className="bg-cyber-card/80 border border-cyber-accent/20 rounded-2xl p-8 backdrop-blur-sm shadow-2xl">
                      <h3 className="text-sm font-black uppercase tracking-[0.3em] text-white italic mb-8 border-b border-cyber-accent/10 pb-4">Infrastructure_Health</h3>
                      <div className="space-y-8">
                         {topology.nodes.filter(n => n.type === 'node').slice(0, 4).map((node, i) => (
                           <div key={i} className="space-y-2">
                              <div className="flex justify-between items-center px-1">
                                 <span className="text-[10px] font-black text-white uppercase italic">{node.name}</span>
                                 <span className="text-[9px] font-black text-cyber-neon uppercase tracking-widest">98%</span>
                              </div>
                              <div className="h-2 bg-black/60 rounded-full overflow-hidden border border-cyber-accent/20">
                                 <div className="h-full bg-gradient-to-r from-cyber-accent to-cyber-neon w-[98%] shadow-[0_0_10px_rgba(0,255,157,0.3)]" />
                              </div>
                           </div>
                         ))}
                      </div>
                   </div>
                </div>
              </>
            )}

            {activeTab === 'Nodes' && (
              <div className="space-y-8">
                <div className="flex flex-col gap-2 border-l-4 border-cyber-accent pl-6 mb-10">
                   <h1 className="text-4xl font-black text-white uppercase italic tracking-tighter">Compute_Grid</h1>
                   <p className="text-xs text-cyber-accent font-black uppercase tracking-[0.3em] opacity-60 italic">Physical and virtualized node management</p>
                </div>

                <div className="grid gap-6">
                  {topology.nodes.filter(n => n.type === 'node').map((node, i) => (
                    <div key={i} className="bg-cyber-card/80 border border-cyber-accent/20 rounded-2xl p-8 backdrop-blur-sm shadow-2xl overflow-hidden relative group">
                      <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity">
                         <Server size={120} />
                      </div>
                      
                      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8 relative z-10">
                        <div className="flex items-center gap-6">
                          <div className="p-4 bg-cyber-accent/10 border border-cyber-accent/30 rounded-2xl text-cyber-accent">
                            <Server size={32} />
                          </div>
                          <div>
                            <h3 className="text-2xl font-black text-white uppercase italic tracking-tight">{node.name || node.id}</h3>
                            <div className="flex items-center gap-4 mt-1">
                               <StatusBadge status={node.status} />
                               <span className="text-[9px] text-cyber-accent/60 font-black uppercase tracking-widest">{node.metrics?.os || 'Linux_Kernel'}</span>
                            </div>
                          </div>
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 border-l border-cyber-accent/10 pl-8">
                           <div className="flex flex-col">
                              <span className="text-[8px] text-cyber-accent uppercase font-black tracking-widest mb-1">CPU_Capacity</span>
                              <span className="text-lg font-black text-white tracking-tighter">{node.metrics?.cpu || '0'} cores</span>
                           </div>
                           <div className="flex flex-col">
                              <span className="text-[8px] text-cyber-accent uppercase font-black tracking-widest mb-1">MEM_Capacity</span>
                              <span className="text-lg font-black text-white tracking-tighter">{node.metrics?.memory || '0'}</span>
                           </div>
                           <div className="flex flex-col">
                              <span className="text-[8px] text-cyber-accent uppercase font-black tracking-widest mb-1">System_Uptime</span>
                              <span className="text-lg font-black text-cyber-neon tracking-tighter">{node.metrics?.uptime || '0d'}</span>
                           </div>
                           <div className="flex flex-col">
                              <span className="text-[8px] text-cyber-accent uppercase font-black tracking-widest mb-1">Kernel_Version</span>
                              <span className="text-[10px] font-mono text-white/60 truncate max-w-[120px]">{node.metrics?.kernel || 'Unknown'}</span>
                           </div>
                        </div>
                      </div>

                      <div className="mt-10 pt-8 border-t border-cyber-accent/10">
                         <div className="flex items-center gap-2 mb-6">
                            <Layers size={14} className="text-cyber-neon" />
                            <h4 className="text-[10px] font-black uppercase tracking-[0.3em] text-white/80 italic">Hosted_Workloads (Pods)</h4>
                         </div>
                         <div className="flex flex-wrap gap-3">
                            {topology.nodes.filter(p => p.type === 'pod' && (p.node === node.name || p.node === node.id)).map((pod, pi) => (
                              <div key={pi} className="flex items-center gap-3 px-4 py-2 bg-black/40 border border-cyber-accent/10 rounded-xl hover:border-cyber-neon/30 transition-all cursor-default group/pod">
                                 <div className={`w-1.5 h-1.5 rounded-full ${pod.status === 'Running' ? 'bg-cyber-neon' : 'bg-red-500'}`} />
                                 <div className="flex flex-col">
                                    <span className="text-[10px] font-black text-white group-hover/pod:text-cyber-neon transition-colors">{pod.name}</span>
                                    <span className="text-[7px] text-cyber-accent/40 font-bold uppercase tracking-tighter">{pod.ip || '0.0.0.0'}</span>
                                 </div>
                              </div>
                            ))}
                         </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'Pods' && (
              <div className="space-y-8">
                <div className="flex flex-col gap-2 border-l-4 border-cyber-accent pl-6 mb-10">
                   <h1 className="text-4xl font-black text-white uppercase italic tracking-tighter">Active_Pods_Matrix</h1>
                   <p className="text-xs text-cyber-accent font-black uppercase tracking-[0.3em] opacity-60 italic">Real-time resource allocation and network activity</p>
                </div>

                <div className="grid gap-8">
                  {Object.entries(podsByNamespace).map(([namespace, podsInNs]) => (
                    <div key={namespace} className="bg-cyber-card/80 border border-cyber-accent/20 rounded-2xl p-8 backdrop-blur-sm shadow-2xl">
                       <div className="flex items-center justify-between mb-6 border-b border-cyber-accent/10 pb-4">
                          <h3 className="text-xl font-black text-white uppercase italic tracking-tight flex items-center gap-3">
                            <Layers size={20} className="text-cyber-neon" />
                            Namespace: {namespace}
                          </h3>
                          <span className="text-[10px] font-black text-cyber-accent uppercase tracking-widest bg-cyber-accent/10 px-3 py-1 rounded-full border border-cyber-accent/30">
                            {podsInNs.length} Pods
                          </span>
                       </div>
                       <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                          {podsInNs.map((pod, pi) => (
                            <div key={pi} className="bg-black/40 border border-cyber-accent/10 rounded-xl p-4 flex flex-col gap-3 hover:border-cyber-neon/30 transition-all cursor-default group/pod">
                               <div className="flex justify-between items-start">
                                  <div className="flex items-center gap-3">
                                     <Layers size={16} className="text-cyber-neon" />
                                     <span className="text-sm font-black text-white group-hover/pod:text-cyber-neon transition-colors uppercase italic">{pod.name}</span>
                                  </div>
                                  <StatusBadge status={pod.status} />
                               </div>
                               <div className="grid grid-cols-2 gap-3 text-xs font-mono border-t border-cyber-accent/10 pt-3">
                                  <div className="flex flex-col gap-1">
                                     <span className="text-[8px] text-cyber-accent/60 uppercase font-bold tracking-wider">CPU_Usage</span>
                                     <span className="text-white font-black">{pod.metrics?.cpu_usage || '0m'}</span>
                                  </div>
                                  <div className="flex flex-col gap-1">
                                     <span className="text-[8px] text-cyber-accent/60 uppercase font-bold tracking-wider">Mem_Usage</span>
                                     <span className="text-white font-black">{pod.metrics?.memory_usage || '0Mi'}</span>
                                  </div>
                                  <div className="flex flex-col gap-1">
                                     <span className="text-[8px] text-cyber-accent/60 uppercase font-bold tracking-wider">IP_Address</span>
                                     <span className="text-white font-black">{pod.ip || 'N/A'}</span>
                                  </div>
                                  <div className="flex flex-col gap-1">
                                     <span className="text-[8px] text-cyber-accent/60 uppercase font-bold tracking-wider">Packets_Tx</span>
                                     <span className="text-cyber-neon font-black">{pod.metrics?.packet_count || '0'}</span>
                                  </div>
                               </div>
                               {pod.node && (
                                 <div className="text-[8px] text-cyber-accent/40 font-bold uppercase tracking-wider border-t border-cyber-accent/10 pt-2 mt-auto">
                                    Node: {pod.node}
                                 </div>
                               )}
                            </div>
                          ))}
                       </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'Topology' && (
              <div className="h-[calc(100vh-200px)] w-full bg-cyber-card/50 border border-cyber-accent/20 rounded-3xl overflow-hidden backdrop-blur-sm shadow-2xl relative">
                <div className="absolute top-6 left-6 z-10 flex items-center gap-4">
                   <div className="bg-black/80 backdrop-blur-md border border-cyber-accent/30 px-6 py-3 rounded-2xl flex items-center gap-4">
                      <div className="flex items-center gap-2">
                         <div className="w-2 h-2 rounded-full bg-cyan-400" />
                         <span className="text-[9px] font-black uppercase text-white tracking-widest">Pod</span>
                      </div>
                      <div className="flex items-center gap-2">
                         <div className="w-2 h-2 rounded-full bg-purple-500" />
                         <span className="text-[9px] font-black uppercase text-white tracking-widest">Service</span>
                      </div>
                      <div className="flex items-center gap-2">
                         <div className="w-2 h-2 rounded-full bg-white/50" />
                         <span className="text-[9px] font-black uppercase text-white tracking-widest">Node</span>
                      </div>
                   </div>
                </div>
                <ReactFlow 
                  nodes={topology.nodes} 
                  edges={topology.edges}
                >
                  <Background color="#7000ff" opacity={0.05} gap={20} size={1} />
                  <Controls className="bg-cyber-card border-cyber-accent/30 text-cyber-neon" />
                </ReactFlow>
              </div>
            )}

            {activeTab === 'Flows' && (
              <div className="space-y-8">
                <div className="flex justify-between items-end mb-4 border-l-4 border-cyber-accent pl-6">
                   <div>
                      <h1 className="text-4xl font-black text-white uppercase italic tracking-tighter">Flow_Matrix</h1>
                      <p className="text-xs text-cyber-accent font-black uppercase tracking-[0.3em] opacity-60 italic">Deep socket-level network analysis</p>
                   </div>
                   <div className="flex items-center gap-4 bg-black/40 border border-cyber-accent/20 px-4 py-2 rounded-xl">
                      <Search size={16} className="text-cyber-accent/50" />
                      <input type="text" placeholder="Filter_Streams..." className="bg-transparent border-none text-[10px] font-black focus:outline-none w-48 placeholder-cyber-accent/20 uppercase italic" />
                   </div>
                </div>

                <div className="bg-cyber-card/80 border border-cyber-accent/20 rounded-2xl overflow-hidden shadow-2xl">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="bg-cyber-accent/10 border-b border-cyber-accent/20 text-cyber-accent text-[10px] font-black tracking-[0.3em] uppercase italic">
                        <th className="p-6">Source_Origin</th>
                        <th className="p-6">Vector_Path</th>
                        <th className="p-6">Destination_Target</th>
                        <th className="p-6">Protocol_Signature</th>
                        <th className="p-6 text-right">Traffic_Intensity</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cyber-accent/10">
                      {flows.map((flow, i) => (
                        <tr key={i} className="hover:bg-cyber-neon/5 transition-all group cursor-default">
                          <td className="p-6">
                             <div className="flex flex-col">
                                <span className="text-sm font-black text-white group-hover:text-cyber-neon transition-colors uppercase italic">{flow.source}</span>
                                <span className="text-[8px] text-cyber-accent/40 font-bold uppercase tracking-widest mt-1">IPV4_DATA_STREAM</span>
                             </div>
                          </td>
                          <td className="p-6">
                             <div className="flex items-center gap-4">
                                <div className="h-px w-16 bg-cyber-accent/20 relative">
                                   <div className="absolute top-1/2 right-0 -translate-y-1/2 w-2 h-2 border-t-2 border-r-2 border-cyber-neon rotate-45 animate-pulse" />
                                </div>
                             </div>
                          </td>
                          <td className="p-6">
                             <div className="flex flex-col">
                                <span className="text-sm font-black text-white group-hover:text-cyber-neon transition-colors uppercase italic">{flow.dest}</span>
                                <span className="text-[8px] text-cyber-accent/40 font-bold uppercase tracking-widest mt-1">REMOTE_SERVICE_ENDPOINT</span>
                             </div>
                          </td>
                          <td className="p-6">
                             <div className="inline-flex items-center gap-2 px-3 py-1 bg-black/40 border border-cyber-accent/20 rounded-full">
                                <span className="text-[9px] font-mono text-white">{flow.proto.toUpperCase()}</span>
                                <span className="text-[9px] font-black text-cyber-accent">:{flow.port}</span>
                             </div>
                          </td>
                          <td className="p-6 text-right">
                             <div className="flex flex-col items-end">
                                <span className="text-sm font-black text-cyber-neon glow-text tracking-tighter">{flow.count} PKTS</span>
                                <div className="w-20 h-1 bg-black/40 rounded-full mt-1 overflow-hidden">
                                   <div className="h-full bg-cyber-neon w-[60%] animate-shimmer" />
                                </div>
                             </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeTab === 'Security' && (
              <div className="space-y-6">
                <div className="flex justify-between items-end mb-4 border-l-4 border-red-500 pl-6">
                   <div>
                      <h1 className="text-4xl font-black text-white uppercase italic tracking-tighter">Security_View</h1>
                      <p className="text-xs text-red-500 font-black uppercase tracking-[0.3em] opacity-60 italic">eBPF-powered runtime security monitoring</p>
                   </div>
                   <div className="flex items-center gap-3">
                      <button 
                        onClick={fetchSecurityData}
                        className="flex items-center gap-2 px-4 py-2 bg-cyber-neon/10 border border-cyber-neon/30 rounded-lg text-[10px] font-bold uppercase tracking-wider text-cyber-neon hover:bg-cyber-neon/20 transition-colors">
                        <RefreshCw size={12} />
                        Refresh
                      </button>
                     <button className="flex items-center gap-2 px-4 py-2 bg-red-500/10 border border-red-500/30 rounded-lg text-[10px] font-bold uppercase tracking-wider text-red-500 hover:bg-red-500/20 transition-colors">
                       <ShieldAlert size={12} />
                       Configure
                     </button>
                   </div>
                </div>

                <div className="grid grid-cols-4 gap-4">
                  <div 
                    onClick={() => setSelectedSecurityDetail('total')}
                    className="p-6 rounded-xl border bg-cyber-card backdrop-blur-sm border-cyber-accent/20 hover:scale-[1.02] transition-all cursor-pointer hover:border-cyber-neon/50"
                  >
                    <div className="flex items-center gap-4">
                      <div className="p-3 rounded-lg bg-cyber-accent/10 border border-cyber-accent/20">
                        <Shield size={20} className="text-cyber-accent" />
                      </div>
                      <div>
                        <div className="text-[10px] font-black uppercase tracking-widest text-cyber-accent/60 italic">Total_Events</div>
                        <div className="text-2xl font-black tracking-tighter text-white">{securityData.events.length}</div>
                        <div className="text-[8px] font-bold uppercase tracking-tighter opacity-40 mt-1">Security_Monitored</div>
                      </div>
                    </div>
                  </div>
                  <div 
                    onClick={() => setSelectedSecurityDetail('critical')}
                    className="p-6 rounded-xl border bg-cyber-card backdrop-blur-sm border-red-500/20 hover:scale-[1.02] transition-all cursor-pointer hover:border-red-500/50"
                  >
                    <div className="flex items-center gap-4">
                      <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                        <AlertTriangle size={20} className="text-red-500" />
                      </div>
                      <div>
                        <div className="text-[10px] font-black uppercase tracking-widest text-red-500/60 italic">Critical</div>
                        <div className="text-2xl font-black tracking-tighter text-red-500">{securityData.events.filter(e => e.severity === 'CRITICAL').length}</div>
                        <div className="text-[8px] font-bold uppercase tracking-tighter opacity-40 mt-1">Immediate_Action</div>
                      </div>
                    </div>
                  </div>
                  <div 
                    onClick={() => setSelectedSecurityDetail('high')}
                    className="p-6 rounded-xl border bg-cyber-card backdrop-blur-sm border-orange-500/20 hover:scale-[1.02] transition-all cursor-pointer hover:border-orange-500/50"
                  >
                    <div className="flex items-center gap-4">
                      <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/20">
                        <Lock size={20} className="text-orange-500" />
                      </div>
                      <div>
                        <div className="text-[10px] font-black uppercase tracking-widest text-orange-500/60 italic">High_Alerts</div>
                        <div className="text-2xl font-black tracking-tighter text-orange-500">{securityData.events.filter(e => e.severity === 'HIGH').length}</div>
                        <div className="text-[8px] font-bold uppercase tracking-tighter opacity-40 mt-1">Requires_Attention</div>
                      </div>
                    </div>
                  </div>
                  <div 
                    onClick={() => setSelectedSecurityDetail('drift')}
                    className="p-6 rounded-xl border bg-cyber-card backdrop-blur-sm border-yellow-500/20 hover:scale-[1.02] transition-all cursor-pointer hover:border-yellow-500/50"
                  >
                    <div className="flex items-center gap-4">
                      <div className="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
                        <Activity size={20} className="text-yellow-500" />
                      </div>
                      <div>
                        <div className="text-[10px] font-black uppercase tracking-widest text-yellow-500/60 italic">Baseline_Drift</div>
                        <div className="text-2xl font-black tracking-tighter text-yellow-500">{securityData.drift?.total_drifts || 0}</div>
                        <div className="text-[8px] font-bold uppercase tracking-tighter opacity-40 mt-1">Deviations_Detected</div>
                      </div>
                    </div>
                  </div>
                </div>

                {selectedSecurityDetail && (
                  <div className="mt-6 p-6 rounded-xl border bg-cyber-card/95 backdrop-blur-sm border-cyber-neon/30">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-sm font-black uppercase tracking-wider flex items-center gap-2">
                        {selectedSecurityDetail === 'total' && <><Shield size={16} className="text-cyber-accent" /> ALL_SECURITY_EVENTS</>}
                        {selectedSecurityDetail === 'critical' && <><AlertTriangle size={16} className="text-red-500" /> CRITICAL_ALERTS</>}
                        {selectedSecurityDetail === 'high' && <><Lock size={16} className="text-orange-500" /> HIGH_PRIORITY_ALERTS</>}
                        {selectedSecurityDetail === 'drift' && <><Activity size={16} className="text-yellow-500" /> BASELINE_DRIFT_ANALYSIS</>}
                      </h3>
                      <button 
                        onClick={() => setSelectedSecurityDetail(null)}
                        className="text-cyber-accent/60 hover:text-white text-xl leading-none"
                      >
                        ×
                      </button>
                    </div>
                    <div className="max-h-96 overflow-y-auto">
                      {selectedSecurityDetail === 'total' && (
                        <div className="space-y-2">
                          <div className="text-[10px] text-cyber-accent/60 mb-3">Showing all {securityData.events.length} events</div>
                          {securityData.events.map((event, idx) => (
                            <div key={event.event_id || idx} className="p-3 rounded-lg bg-black/20 border border-cyber-accent/10">
                              <div className="flex items-center gap-2 mb-1">
                                <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                                  event.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-500' :
                                  event.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-500' :
                                  event.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-500' :
                                  'bg-cyber-accent/20 text-cyber-accent'
                                }`}>{event.severity}</span>
                                <span className="text-[10px] text-white/80">{event.event_type}</span>
                              </div>
                              <div className="text-[9px] text-cyber-accent/50">
                                {event.namespace}/{event.pod_name} • {event.comm} • {event.timestamp?.split('T')[1]?.split('.')[0] || 'unknown'}
                              </div>
                              {event.path && <div className="text-[8px] text-cyber-accent/40 mt-1 font-mono">Path: {event.path}</div>}
                              {event.src_ip && <div className="text-[8px] text-cyber-accent/40 font-mono">{event.src_ip} → {event.dst_ip}:{event.dst_port}</div>}
                            </div>
                          ))}
                        </div>
                      )}
                      {selectedSecurityDetail === 'critical' && (
                        <div className="space-y-2">
                          {securityData.events.filter(e => e.severity === 'CRITICAL').length === 0 ? (
                            <div className="text-center py-8 text-cyber-accent/40">
                              <Shield size={32} className="mx-auto mb-2" />
                              <p>No critical alerts</p>
                            </div>
                          ) : (
                            <>
                              <div className="text-[10px] text-red-500/60 mb-3">{securityData.events.filter(e => e.severity === 'CRITICAL').length} critical alerts require immediate action</div>
                              {securityData.events.filter(e => e.severity === 'CRITICAL').map((event, idx) => (
                                <div key={event.event_id || idx} className="p-4 rounded-lg bg-red-500/5 border border-red-500/20">
                                  <div className="flex items-center gap-2 mb-2">
                                    <AlertTriangle size={14} className="text-red-500" />
                                    <span className="text-xs font-bold text-red-400">{event.event_type?.replace(/_/g, ' ')}</span>
                                  </div>
                                  <div className="text-[10px] text-white/70 mb-2">
                                    {event.namespace}/{event.pod_name} • {event.comm}
                                  </div>
                                  {event.details && (
                                    <div className="text-[9px] font-mono text-cyber-accent/60 bg-black/30 p-2 rounded">
                                      {event.path || JSON.stringify(event.details)}
                                    </div>
                                  )}
                                  <div className="text-[8px] text-red-500/50 mt-2">{event.timestamp?.split('T')[1]?.split('.')[0] || 'unknown'}</div>
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      )}
                      {selectedSecurityDetail === 'high' && (
                        <div className="space-y-2">
                          {securityData.events.filter(e => e.severity === 'HIGH').length === 0 ? (
                            <div className="text-center py-8 text-cyber-accent/40">
                              <Lock size={32} className="mx-auto mb-2" />
                              <p>No high priority alerts</p>
                            </div>
                          ) : (
                            <>
                              <div className="text-[10px] text-orange-500/60 mb-3">{securityData.events.filter(e => e.severity === 'HIGH').length} high priority alerts</div>
                              {securityData.events.filter(e => e.severity === 'HIGH').map((event, idx) => (
                                <div key={event.event_id || idx} className="p-4 rounded-lg bg-orange-500/5 border border-orange-500/20">
                                  <div className="flex items-center gap-2 mb-2">
                                    <Lock size={14} className="text-orange-500" />
                                    <span className="text-xs font-bold text-orange-400">{event.event_type?.replace(/_/g, ' ')}</span>
                                  </div>
                                  <div className="text-[10px] text-white/70 mb-2">
                                    {event.namespace}/{event.pod_name} • {event.comm}
                                  </div>
                                  {event.details && (
                                    <div className="text-[9px] font-mono text-cyber-accent/60 bg-black/30 p-2 rounded">
                                      {event.path || JSON.stringify(event.details)}
                                    </div>
                                  )}
                                  <div className="text-[8px] text-orange-500/50 mt-2">{event.timestamp?.split('T')[1]?.split('.')[0] || 'unknown'}</div>
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      )}
                      {selectedSecurityDetail === 'drift' && (
                        <div className="space-y-4">
                          <div className="text-[10px] text-yellow-500/60 mb-3">Runtime drift analysis based on learned baseline</div>
                          <div className="grid grid-cols-3 gap-4 mb-4">
                            <div className="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-center">
                              <div className="text-xl font-black text-yellow-500">{securityData.drift?.total_drifts || 0}</div>
                              <div className="text-[9px] text-yellow-500/60">Total Drifts</div>
                            </div>
                            <div className="p-3 rounded-lg bg-cyber-neon/10 border border-cyber-neon/20 text-center">
                              <div className="text-xl font-black text-cyber-neon">{securityData.drift?.baseline_compliance || 100}%</div>
                              <div className="text-[9px] text-cyber-neon/60">Compliance</div>
                            </div>
                            <div className="p-3 rounded-lg bg-cyber-accent/10 border border-cyber-accent/20 text-center">
                              <div className="text-xl font-black text-cyber-accent">{securityData.drift?.containers?.length || 0}</div>
                              <div className="text-[9px] text-cyber-accent/60">Containers</div>
                            </div>
                          </div>
                          <div className="text-[10px] font-bold text-white/80 mb-2">CONTAINER DRIFT BREAKDOWN:</div>
                          {securityData.drift?.containers?.map((container, idx) => (
                            <div key={idx} className="p-3 rounded-lg bg-black/20 border border-yellow-500/10 mb-2">
                              <div className="flex items-center justify-between mb-2">
                                <span className="text-[10px] font-bold text-white/80">{container.name}</span>
                                <span className="text-[9px] text-yellow-500/60">
                                  {container.violations} violations / {container.accesses} accesses
                                </span>
                              </div>
                              <div className="w-full h-2 bg-black/40 rounded-full overflow-hidden">
                                <div 
                                  className="h-full bg-gradient-to-r from-yellow-500 to-red-500 transition-all"
                                  style={{ width: `${Math.min(100, (container.violations / container.accesses) * 100)}%` }}
                                />
                              </div>
                            </div>
                          ))}
                          {(!securityData.drift?.containers || securityData.drift.containers.length === 0) && (
                            <div className="text-center py-8 text-cyber-accent/40">
                              <Activity size={32} className="mx-auto mb-2" />
                              <p>No container drift data available</p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-6">
                  <div className="bg-cyber-card border border-cyber-accent/20 rounded-xl overflow-hidden">
                    <div className="p-4 border-b border-cyber-accent/10 flex items-center gap-3">
                      <ShieldAlert size={18} className="text-red-500" />
                      <h2 className="text-sm font-black uppercase tracking-wider">Alert_Feed</h2>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyber-neon/20 text-cyber-neon border border-cyber-neon/30">
                        {securityData.events.length} Events
                      </span>
                    </div>
                    <div className="max-h-80 overflow-y-auto">
                      {securityData.events.length === 0 ? (
                        <div className="p-8 text-center text-cyber-accent/40">
                          <Shield size={24} className="mx-auto mb-2 text-cyber-neon" />
                          <p className="text-sm">No security events detected</p>
                          <p className="text-[10px] mt-2 opacity-60">eBPF monitoring active</p>
                        </div>
                      ) : (
                        <div className="divide-y divide-cyber-accent/10">
                          {securityData.events.slice(0, 10).map((event, idx) => (
                            <div key={event.event_id || idx} className="p-4 hover:bg-cyber-accent/5 transition-colors">
                              <div className="flex items-start gap-3">
                                <div className={`p-2 rounded-lg text-[9px] font-bold uppercase px-2 ${
                                  event.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-500 border border-red-500/30' :
                                  event.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-500 border border-orange-500/30' :
                                  event.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-500 border border-yellow-500/30' :
                                  'bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/30'
                                }`}>
                                  {event.severity}
                                </div>
                                <div className="flex-1 min-w-0">
                                  <div className="text-xs font-bold text-white/80 truncate">{event.event_type?.replace(/_/g, ' ')}</div>
                                  <div className="text-[10px] text-cyber-accent/60 mt-1">
                                    {event.namespace && <span>{event.namespace} / </span>}
                                    {event.pod_name || event.comm}
                                  </div>
                                  {event.details && (
                                    <div className="mt-2 p-2 bg-black/20 rounded text-[9px] font-mono text-cyber-accent/60 truncate">
                                      {event.path || JSON.stringify(event.details).slice(0, 80)}
                                    </div>
                                  )}
                                </div>
                                <div className="text-[9px] text-cyber-accent/40">
                                  {event.timestamp?.split('T')[1]?.split('.')[0] || 'now'}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="bg-cyber-card border border-cyber-accent/20 rounded-xl overflow-hidden">
                    <div className="p-4 border-b border-cyber-accent/10 flex items-center gap-3">
                      <Activity size={18} className="text-orange-500" />
                      <h2 className="text-sm font-black uppercase tracking-wider">Runtime_Drift_Status</h2>
                    </div>
                    <div className="p-4 space-y-4">
                      <div className="flex items-center justify-between p-4 bg-black/20 rounded-lg border border-cyber-accent/10">
                        <div className="flex items-center gap-3">
                          <div className={`w-3 h-3 rounded-full ${(securityData.drift?.total_drifts || 0) > 0 ? 'bg-orange-500 animate-pulse' : 'bg-cyber-neon'}`} />
                          <span className="text-sm font-bold">{(securityData.drift?.total_drifts || 0) > 0 ? 'Drift_Detected' : 'Baseline_Normal'}</span>
                        </div>
                        <div className="text-2xl font-black text-cyber-neon">
                          {securityData.drift?.baseline_compliance || 100}%
                          <span className="text-[10px] text-cyber-accent/40 ml-1">compliant</span>
                        </div>
                      </div>
                      <div className="flex items-center justify-between p-3 bg-black/20 rounded-lg border border-cyber-accent/10">
                        <div>
                          <div className="text-xs font-bold">Learning_Mode</div>
                          <div className="text-[10px] text-cyber-accent/60">
                            {securityData.baseline?.learning_enabled ? 'Capturing baseline...' : 'Capture baseline behavior'}
                          </div>
                          {securityData.baseline?.learning_enabled && (
                            <div className="text-[9px] text-cyber-neon mt-1">
                              {securityData.baseline.paths_captured || 0} paths, {securityData.baseline.processes_captured || 0} processes captured
                            </div>
                          )}
                        </div>
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input 
                            type="checkbox" 
                            className="sr-only peer" 
                            checked={securityData.baseline?.learning_enabled || false}
                            onChange={toggleBaselineLearning}
                          />
                          <div className={`w-11 h-6 rounded-full transition-all ${
                            securityData.baseline?.learning_enabled 
                              ? 'bg-cyber-neon/30 border-cyber-neon' 
                              : 'bg-cyber-accent/20'
                          } peer-focus:outline-none peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:rounded-full after:h-5 after:w-5 after:transition-all ${
                            securityData.baseline?.learning_enabled 
                              ? 'after:bg-cyber-neon' 
                              : 'after:bg-cyber-accent'
                          }`} />
                        </label>
                      </div>
                      {securityData.baseline?.learning_enabled && (securityData.baseline.paths_captured > 0 || securityData.baseline.processes_captured > 0) && (
                        <div className="mt-3 p-3 bg-cyber-neon/5 rounded-lg border border-cyber-neon/20">
                          <div className="text-[10px] font-bold text-cyber-neon mb-2">BASELINE SNAPSHOT</div>
                          {securityData.baseline.paths_captured > 0 && (
                            <div className="mb-2">
                              <div className="text-[9px] text-cyber-accent/60 mb-1">PATHS:</div>
                              <div className="flex flex-wrap gap-1">
                                {Array.isArray(securityData.baseline.baseline_paths) && securityData.baseline.baseline_paths.slice(0, 5).map((p, i) => (
                                  <span key={i} className="text-[8px] px-1 py-0.5 bg-cyber-neon/10 rounded text-cyber-neon/80 font-mono">{p}</span>
                                ))}
                              </div>
                            </div>
                          )}
                          {securityData.baseline.processes_captured > 0 && (
                            <div>
                              <div className="text-[9px] text-cyber-accent/60 mb-1">PROCESSES:</div>
                              <div className="flex flex-wrap gap-1">
                                {Array.isArray(securityData.baseline.baseline_processes) && securityData.baseline.baseline_processes.slice(0, 5).map((p, i) => (
                                  <span key={i} className="text-[8px] px-1 py-0.5 bg-purple-500/10 rounded text-purple-400/80 font-mono">{p}</span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-6">
                  <div className="bg-cyber-card border border-cyber-accent/20 rounded-xl overflow-hidden">
                    <div className="p-4 border-b border-cyber-accent/10 flex items-center gap-3">
                      <Globe size={18} className="text-purple-500" />
                      <h2 className="text-sm font-black uppercase tracking-wider">DNS_Threat_Analysis</h2>
                    </div>
                    <div className="p-4">
                      <div className="grid grid-cols-3 gap-3 mb-4">
                        <div className="p-3 bg-red-500/10 rounded-lg border border-red-500/20 text-center">
                          <div className="text-xl font-black text-red-500">{securityData.dns?.high_entropy || 0}</div>
                          <div className="text-[9px] text-red-500/60 uppercase">High_Entropy</div>
                        </div>
                        <div className="p-3 bg-orange-500/10 rounded-lg border border-orange-500/20 text-center">
                          <div className="text-xl font-black text-orange-500">{securityData.dns?.nxdomain_rate || 0}%</div>
                          <div className="text-[9px] text-orange-500/60 uppercase">NXDOMAIN</div>
                        </div>
                        <div className="p-3 bg-purple-500/10 rounded-lg border border-purple-500/20 text-center">
                          <div className="text-xl font-black text-purple-500">{securityData.dns?.suspicious_tlds || 0}</div>
                          <div className="text-[9px] text-purple-500/60 uppercase">Suspicious</div>
                        </div>
                      </div>
                      {securityData.dns?.recent && securityData.dns.recent.length > 0 ? (
                        <div className="space-y-2">
                          {securityData.dns.recent.slice(0, 3).map((event, i) => (
                            <div key={i} className="p-3 bg-black/20 rounded-lg border border-cyber-accent/10">
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-[10px] font-bold text-purple-400">DNS_QUERY</span>
                                <span className="text-[9px] text-cyber-accent/40">{event.details?.entropy || 0} entropy</span>
                              </div>
                              <div className="text-[9px] font-mono text-cyber-accent/60 truncate">{event.details?.query || 'Unknown query'}</div>
                              <div className="text-[8px] text-red-500/60 mt-1">{event.details?.threat || 'Potential threat'}</div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="p-6 text-center text-cyber-accent/40 border border-dashed border-cyber-accent/20 rounded-lg">
                          <Globe size={20} className="mx-auto mb-2 opacity-40" />
                          <p className="text-xs">No suspicious DNS activity detected</p>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="bg-cyber-card border border-cyber-accent/20 rounded-xl overflow-hidden">
                    <div className="p-4 border-b border-cyber-accent/10 flex items-center gap-3">
                      <Lock size={18} className="text-red-500" />
                      <h2 className="text-sm font-black uppercase tracking-wider">Sensitive_Path_Access</h2>
                    </div>
                    <div className="p-4">
                      {securityData.sensitive && securityData.sensitive.length > 0 ? (
                        <div className="space-y-2">
                          {securityData.sensitive.slice(0, 5).map((event, i) => (
                            <div key={i} className="p-2 rounded-lg border bg-red-500/5 border-red-500/20 flex items-center gap-2">
                              <Lock size={12} className="text-red-500" />
                              <span className="text-[9px] font-mono text-red-500/80">{event.path || 'Unknown path'}</span>
                              <span className="text-[8px] text-cyber-accent/40 ml-auto">{event.comm}</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="grid grid-cols-2 gap-2 mb-4">
                          {['/etc/shadow', '169.254.169.254', '/run/secrets/', 'admin.conf'].map((path, i) => (
                            <div key={i} className="p-2 rounded-lg border bg-red-500/5 border-red-500/20 flex items-center gap-2">
                              <Lock size={12} className="text-red-500" />
                              <span className="text-[9px] font-mono text-red-500/80">{path}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      <div className="p-6 text-center text-cyber-accent/40 border border-dashed border-cyber-accent/20 rounded-lg">
                        <Lock size={20} className="mx-auto mb-2 opacity-40" />
                        <p className="text-xs">{securityData.sensitive && securityData.sensitive.length > 0 ? `${securityData.sensitive.length} access attempt(s) detected` : 'No sensitive path access detected'}</p>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-cyber-card border border-cyber-accent/20 rounded-xl overflow-hidden">
                  <div className="p-4 border-b border-cyber-accent/10 flex items-center gap-3">
                    <Network size={18} className="text-cyber-accent" />
                    <h2 className="text-sm font-black uppercase tracking-wider">Security_Modules</h2>
                  </div>
                  <div className="p-4 grid grid-cols-2 gap-4">
                    <div className="p-4 bg-black/20 rounded-lg border border-cyber-accent/10">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="w-2 h-2 rounded-full bg-cyber-neon animate-pulse" />
                        <span className="text-sm font-bold">Socket-to-Process</span>
                      </div>
                      <p className="text-[10px] text-cyber-accent/60">TCP connection tracking with PID/TGID/comm correlation</p>
                    </div>
                    <div className="p-4 bg-black/20 rounded-lg border border-cyber-accent/10">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="w-2 h-2 rounded-full bg-cyber-neon animate-pulse" />
                        <span className="text-sm font-bold">Runtime Drift Detection</span>
                      </div>
                      <p className="text-[10px] text-cyber-accent/60">Baseline learning and deviation detection</p>
                    </div>
                    <div className="p-4 bg-black/20 rounded-lg border border-cyber-accent/10">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="w-2 h-2 rounded-full bg-cyber-neon animate-pulse" />
                        <span className="text-sm font-bold">DNS Threat Monitoring</span>
                      </div>
                      <p className="text-[10px] text-cyber-accent/60">High-entropy subdomain and C2 detection</p>
                    </div>
                    <div className="p-4 bg-black/20 rounded-lg border border-cyber-accent/10">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="w-2 h-2 rounded-full bg-cyber-neon animate-pulse" />
                        <span className="text-sm font-bold">Sensitive Path Access</span>
                      </div>
                      <p className="text-[10px] text-cyber-accent/60">Cloud metadata and secrets monitoring</p>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
      
      <footer className="h-10 border-t border-cyber-accent/10 bg-black/60 flex items-center justify-center px-8 text-[9px] font-black text-cyber-accent/30 uppercase tracking-[0.4em] relative z-10">
        <span className="italic">CLOUDNEXUS_LABS: Lattice</span>
      </footer>
    </div>
  );
}

function NavItem({ icon, label, active = false, open, onClick }) {
  return (
    <div 
      onClick={onClick}
      className={`
        flex items-center gap-5 px-6 py-4 cursor-pointer transition-all group relative overflow-hidden
        ${active ? 'text-cyber-neon border-r-2 border-cyber-neon bg-cyber-neon/5 shadow-[inset_-10px_0_20px_-10px_rgba(0,255,157,0.2)]' : 'text-cyber-accent/40 hover:text-white hover:bg-white/5'}
      `}
    >
      <div className={`transition-all duration-300 ${active ? 'scale-110 drop-shadow-[0_0_8px_rgba(0,255,157,0.5)]' : 'group-hover:scale-110'}`}>
        {icon}
      </div>
      {open && <span className="text-[11px] font-black uppercase tracking-[0.3em] italic">{label}</span>}
      {!open && <div className="absolute left-1/2 -translate-x-1/2 bottom-1 w-1 h-1 rounded-full bg-current opacity-20" />}
    </div>
  );
}
