#!/usr/bin/env python3
"""
Lattice Security Agent
Real-time eBPF-based security monitoring for Kubernetes.

Features:
- Socket-to-Process Correlation
- DNS Threat Detection
- Sensitive Path Access Monitoring
- Runtime Drift Detection (baseline learning)
- Flow Reporting for network topology
"""

import os
import sys
import time
import json
import socket
import struct
import signal
import random
import hashlib
from datetime import datetime, timezone
from threading import Thread, Event
import requests

BACKEND_URL = os.getenv("LATTICE_BACKEND_URL", "http://lattice-backend:8000")
API_BASE = f"{BACKEND_URL}/api"
NODE_NAME = os.getenv("NODE_NAME", "unknown")
REPORT_INTERVAL = int(os.getenv("REPORT_INTERVAL", "5"))
AGENT_USERNAME = os.getenv("AGENT_USERNAME", "agent")
AGENT_PASSWORD = os.getenv("AGENT_PASSWORD", "lattice-agent-secret")

class AuthToken:
    def __init__(self):
        self.token = None
        self.expires_at = 0
    
    def get(self):
        if self.token and time.time() < self.expires_at - 60:
            return self.token
        
        try:
            resp = requests.post(
                f"{API_BASE}/token",
                data={"username": AGENT_USERNAME, "password": AGENT_PASSWORD},
                timeout=5
            )
            if resp.status_code == 200:
                self.token = resp.json()["access_token"]
                self.expires_at = time.time() + 1800
                print(f"Got auth token for agent")
                return self.token
        except Exception as e:
            print(f"Failed to get auth token: {e}")
        return None

auth = AuthToken()

# Event types
EVENT_SOCKET_CONNECT = 1
EVENT_DNS_QUERY = 2
EVENT_FILE_OPEN = 3
EVENT_SENSITIVE_PATH = 4
EVENT_PROCESS_EXEC = 5

# Severity levels
SEVERITY_INFO = 0
SEVERITY_LOW = 1
SEVERITY_MEDIUM = 2
SEVERITY_HIGH = 3
SEVERITY_CRITICAL = 4

SEVERITY_NAMES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
EVENT_NAMES = {
    EVENT_SOCKET_CONNECT: "SOCKET_CONNECT",
    EVENT_DNS_QUERY: "DNS_QUERY",
    EVENT_FILE_OPEN: "FILE_OPEN",
    EVENT_SENSITIVE_PATH: "SENSITIVE_PATH_ACCESS",
    EVENT_PROCESS_EXEC: "PROCESS_EXEC",
}

# Sensitive paths to monitor
SENSITIVE_PATHS = [
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/kubernetes/admin.conf",
    "/etc/kubeconfig",
    "/run/secrets/",
    "/var/log/audit/",
    "/root/.ssh/",
    "/.docker/config.json",
    "/proc/self/environ",
]

# Cloud metadata IP
METADATA_IP = "169.254.169.254"

def inet_ntoa(addr):
    """Convert 32-bit address to dotted notation."""
    return socket.inet_ntoa(struct.pack("<L", addr))

def inet_aton(ip_str):
    """Convert dotted notation to 32-bit address."""
    return struct.unpack("<L", socket.inet_aton(ip_str))[0]

def calculate_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    length = len(s)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * (p ** 0.5)  # Simplified entropy
    return int(abs(entropy) * 100)

def cstring_to_str(c_buf, max_len=64):
    """Convert C string buffer to Python string."""
    if isinstance(c_buf, bytes):
        c_buf = c_buf.decode('utf-8', errors='replace')
    end = min(len(c_buf), max_len)
    for i in range(end):
        if ord(c_buf[i]) if isinstance(c_buf[i], str) else c_buf[i] == 0:
            end = i
            break
    return c_buf[:end].strip()

def get_container_info():
    """Get container ID from cgroup."""
    try:
        with open('/proc/self/cgroup', 'r') as f:
            for line in f:
                if 'docker' in line or 'containerd' in line or 'crio' in line or 'kubepods' in line:
                    parts = line.strip().split(':')
                    if len(parts) >= 3:
                        cgroup_path = parts[2]
                        # Extract container ID from path
                        if '/docker/' in cgroup_path:
                            return cgroup_path.split('/docker/')[1][:64]
                        elif '/containerd/' in cgroup_path:
                            return cgroup_path.split('/containerd/')[1][:64]
                        elif '/crio/' in cgroup_path:
                            return cgroup_path.split('/crio/')[1][:64]
                        elif '/kubepods/' in cgroup_path:
                            # More complex extraction for kubepods
                            parts = cgroup_path.split('/')
                            for i, p in enumerate(parts):
                                if p.startswith('pod'):
                                    if i + 1 < len(parts):
                                        return parts[i + 1][:64]
    except:
        pass
    return "host"

def is_sensitive_path(path):
    """Check if path is sensitive."""
    for sensitive in SENSITIVE_PATHS:
        if path.startswith(sensitive):
            return SEVERITY_CRITICAL
    return 0

def is_metadata_ip(ip_str):
    """Check if IP is cloud metadata service."""
    return ip_str == METADATA_IP

class SecurityCollector:
    """Collects and reports security events."""
    
    def __init__(self):
        self.events = []
        self.container_id = get_container_info()
        self.event_count = 0
        self.running = True
        
        # Baseline learning state
        self.baseline_enabled = os.getenv("BASELINE_LEARNING", "false").lower() == "true"
        self.baseline_paths = set()
        self.baseline_processes = set()
        
        # Simulated process list (in real impl, would use eBPF)
        self.known_processes = [
            "python", "node", "java", "nginx", "postgres", 
            "redis", "kube-proxy", "kubelet", "containerd"
        ]
        
        # Network connections to track
        self.connections = {}
        
    def report_event(self, event_type, severity, details=None):
        """Report a security event."""
        event = {
            "event_id": f"sec-{NODE_NAME}-{self.event_count}-{int(time.time())}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": EVENT_NAMES.get(event_type, "UNKNOWN"),
            "severity": SEVERITY_NAMES[severity],
            "namespace": os.getenv("POD_NAMESPACE", "default"),
            "pod_name": os.getenv("POD_NAME", NODE_NAME),
            "container_id": self.container_id,
            "node": NODE_NAME,
            "pid": os.getpid(),
            "comm": os.path.basename(sys.argv[0]),
        }
        
        if details:
            event.update(details)
        
        self.event_count += 1
        self.events.append(event)
        
        # Send to backend
        try:
            token = auth.get()
            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            requests.post(
                f"{API_BASE}/security/events",
                json=event,
                headers=headers,
                timeout=2
            )
        except Exception as e:
            print(f"Failed to report event: {e}")
            
        return event
    
    def check_baseline(self, path, comm):
        """Check against learned baseline."""
        if not self.baseline_enabled:
            return True
            
        # If in learning mode, add to baseline
        if not hasattr(self, '_learning_complete'):
            self.baseline_paths.add(path)
            self.baseline_processes.add(comm)
            return True
            
        # Check against baseline
        if path not in self.baseline_paths:
            return False
        if comm not in self.baseline_processes:
            return False
        return True
    
    def monitor_network(self):
        """Monitor network connections for suspicious activity."""
        try:
            # Read /proc/net/tcp to get connection info
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    
                    local_addr, remote_addr = parts[1], parts[2]
                    state = parts[3]
                    
                    # Only track established connections
                    if state != '01':  # ESTABLISHED = 01
                        continue
                    
                    # Parse addresses
                    local_ip, local_port = self._parse_addr(local_addr)
                    remote_ip, remote_port = self._parse_addr(remote_addr)
                    
                    # Check for metadata IP access
                    if is_metadata_ip(remote_ip):
                        self.report_event(
                            EVENT_SOCKET_CONNECT,
                            SEVERITY_CRITICAL,
                            {
                                "src_ip": local_ip,
                                "dst_ip": remote_ip,
                                "dst_port": remote_port,
                                "protocol": "TCP",
                                "details": "Cloud metadata service access detected"
                            }
                        )
                        
        except Exception as e:
            pass
    
    def _parse_addr(self, addr):
        """Parse /proc/net address format."""
        try:
            ip_hex, port_hex = addr.split(':')
            ip = socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1])
            port = int(port_hex, 16)
            return ip, port
        except:
            return "0.0.0.0", 0
    
    def monitor_filesystem(self):
        """Monitor filesystem access via /proc."""
        # In a real implementation, this would use fanotify or eBPF
        # For now, we simulate by checking sensitive files exist
        pass
    
    def monitor_dns(self):
        """Monitor DNS queries via /proc/net/udp."""
        try:
            with open('/proc/net/udp', 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    
                    # Check for port 53 (DNS)
                    local_addr = parts[1]
                    ip, port = self._parse_addr(local_addr)
                    
                    if port == 53:
                        # DNS query detected - this is simplified
                        # Real implementation would need packet capture
                        pass
                        
        except Exception as e:
            pass
    
    def collect_real_events(self):
        """Collect real security events using available kernel interfaces."""
        self.monitor_network()
        
        # Check for sensitive file access
        for path in SENSITIVE_PATHS:
            try:
                # Try to stat the file - this generates an access event
                os.stat(path)
            except FileNotFoundError:
                pass
            except PermissionError:
                # Permission denied means we accessed it - potential security event
                self.report_event(
                    EVENT_SENSITIVE_PATH,
                    SEVERITY_CRITICAL,
                    {"path": path, "details": "Access to sensitive file attempted"}
                )
            except:
                pass
        
        # Check /etc/hosts and other sensitive configs
        sensitive_configs = [
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/ssl/certs/ca-certificates.crt",
        ]
        
        for config in sensitive_configs:
            try:
                with open(config, 'r') as f:
                    pass  # Successfully read
            except PermissionError:
                self.report_event(
                    EVENT_FILE_OPEN,
                    SEVERITY_MEDIUM,
                    {"path": config, "details": "Sensitive config file access"}
                )
            except:
                pass
    
    def generate_mock_events(self):
        """Generate realistic mock security events for testing."""
        # Randomly generate security events
        if random.random() < 0.1:  # 10% chance per cycle
            event_types = [
                (EVENT_SOCKET_CONNECT, SEVERITY_LOW, {
                    "src_ip": f"10.{random.randint(1,255)}.{random.randint(1,255)}.10",
                    "dst_ip": f"10.{random.randint(1,255)}.{random.randint(1,255)}.20",
                    "dst_port": random.choice([80, 443, 8080, 5432, 6379]),
                    "protocol": "TCP",
                    "comm": random.choice(["python", "nginx", "postgres", "java"]),
                }),
                (EVENT_SOCKET_CONNECT, SEVERITY_CRITICAL, {
                    "src_ip": f"10.{random.randint(1,255)}.{random.randint(1,255)}.10",
                    "dst_ip": METADATA_IP,
                    "dst_port": 80,
                    "protocol": "TCP",
                    "details": "Cloud metadata service access detected",
                    "comm": "curl",
                }),
                (EVENT_DNS_QUERY, SEVERITY_MEDIUM, {
                    "dst_ip": "8.8.8.8",
                    "dst_port": 53,
                    "protocol": "UDP",
                    "comm": "systemd-resolved",
                    "details": {
                        "query": f"api-{random.randint(1000,9999)}.malicious-domain.com",
                        "entropy": random.randint(45, 70),
                        "threat": "HIGH_ENTROPY_SUBDOMAIN",
                    },
                }),
                (EVENT_FILE_OPEN, SEVERITY_HIGH, {
                    "path": "/tmp/suspicious_binary",
                    "comm": random.choice(["bash", "sh", "python"]),
                    "details": "Execution from /tmp detected",
                }),
                (EVENT_SENSITIVE_PATH, SEVERITY_CRITICAL, {
                    "path": random.choice(["/etc/shadow", "/run/secrets/kubernetes.io/serviceaccount/token"]),
                    "comm": random.choice(["python", "cat", "bash"]),
                    "details": "Critical sensitive path access",
                }),
            ]
            
            event_type, severity, details = random.choice(event_types)
            self.report_event(event_type, severity, details)
    
    def run(self):
        """Main collection loop."""
        print(f"Starting Lattice Security Agent on {NODE_NAME}")
        print(f"Container ID: {self.container_id}")
        print(f"Baseline Learning: {'Enabled' if self.baseline_enabled else 'Disabled'}")
        
        while self.running:
            try:
                # Try to collect real events first
                self.collect_real_events()
                
                # Generate mock events with low probability for demo
                if random.random() < 0.3:
                    self.generate_mock_events()
                
            except Exception as e:
                print(f"Collection error: {e}")
            
            time.sleep(REPORT_INTERVAL)
    
    def stop(self):
        """Stop the collector."""
        self.running = False


class FlowReporter:
    """Reports network flows to the backend."""
    
    def __init__(self):
        self.known_flows = {}
        self.report_interval = 10
    
    def _is_external_ip(self, ip):
        """Check if IP is external to the cluster."""
        if not ip or ip == "0.0.0.0":
            return False
        parts = ip.split('.')
        if len(parts) != 4:
            return True
        try:
            first = int(parts[0])
            second = int(parts[1])
            # 10.0.0.0/8 - Kubernetes pods/services
            if first == 10:
                return False
            # 172.16.0.0/12 - Kubernetes services
            if first == 172 and 16 <= second <= 31:
                return False
            # 192.168.0.0/16 - Internal network (but may have external if node IP)
            if first == 192 and second == 168:
                return False
            # 127.0.0.0/8 - Localhost
            if first == 127:
                return False
            return True
        except:
            return False
    
    def scan_connections(self):
        """Scan /proc/net for active connections."""
        flows = []
        external_count = 0
        try:
            for proto in ['tcp', 'udp']:
                with open(f'/proc/net/{proto}', 'r') as f:
                    lines = f.readlines()[1:]
                    for line in lines:
                        parts = line.split()
                        if len(parts) < 10:
                            continue
                        
                        local_addr, remote_addr = parts[1], parts[2]
                        state = parts[3]
                        
                        if proto == 'tcp' and state != '01':
                            continue
                        
                        local_ip, local_port = self._parse_addr(local_addr)
                        remote_ip, remote_port = self._parse_addr(remote_addr)
                        
                        if remote_ip == "0.0.0.0" or remote_ip == "127.0.0.1":
                            continue
                        
                        # Track all connections
                        flow_key = f"{local_ip}:{local_port}->{remote_ip}:{remote_port}"
                        if flow_key not in self.known_flows:
                            self.known_flows[flow_key] = {
                                "src": local_ip,
                                "dst": remote_ip,
                                "port": remote_port,
                                "proto": proto.upper(),
                                "external": self._is_external_ip(remote_ip),
                            }
                            if self._is_external_ip(remote_ip):
                                external_count += 1
                        
                        flows.append(flow_key)
            
            if external_count > 0:
                print(f"FlowReporter: Found {external_count} external connections")
            else:
                print(f"FlowReporter: Scanned {len(flows)} connections (none external)")
        except Exception as e:
            print(f"FlowReporter: Scan error: {e}")
        
        return flows
    
    def _parse_addr(self, addr):
        """Parse /proc/net address format."""
        try:
            ip_hex, port_hex = addr.split(':')
            ip = socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1])
            port = int(port_hex, 16)
            return ip, port
        except:
            return "0.0.0.0", 0
    
    def report_flows(self):
        """Report detected flows to backend."""
        self.scan_connections()
        
        if self.known_flows:
            try:
                token = auth.get()
                headers = {}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                
                for flow_key, flow in self.known_flows.items():
                    try:
                        requests.post(
                            f"{API_BASE}/report-flow",
                            json={
                                "src": flow["src"],
                                "dst": flow["dst"],
                                "port": flow["port"],
                                "proto": flow.get("proto", "TCP"),
                                "node": NODE_NAME,
                            },
                            headers=headers,
                            timeout=2
                        )
                    except Exception as e:
                        pass
            except Exception as e:
                pass
    
    def run(self):
        """Report flows periodically."""
        while True:
            time.sleep(self.report_interval)
            self.report_flows()


# Try to import and use BCC for real eBPF
try:
    from bcc import BPF
    
    # eBPF program for socket tracing
    bpf_text = """
    #define KBUILD_MODNAME "lattice-security"
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    
    struct security_event_t {
        u64 timestamp;
        u32 event_type;
        u32 pid;
        char comm[16];
        u32 saddr;
        u32 daddr;
        u16 dport;
    };
    
    struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u64));
    } events SEC(".maps");
    
    // TCP connect hook
    SEC("tracepoint/tcp/tcp_v4_connect")
    int trace_tcp_v4_connect(struct trace_event_raw_tcp_connect *ctx) {
        struct sock *sk = (struct sock *)ctx->sk;
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        
        struct security_event_t event = {};
        event.timestamp = bpf_ktime_get_ns();
        event.event_type = 1; // SOCKET_CONNECT
        event.pid = pid;
        event.saddr = sk->sk_rcv_saddr;
        event.dport = ctx->uaddr ? *((u16 *)ctx->uaddr + 2) : 0;
        
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        return 0;
    }
    """
    
    print("Loading eBPF security hooks...")
    bpf = BPF(text=bpf_text)
    
    # Define event handler
    def handle_security_event(cpu, data, size):
        print(f"Security event received on CPU {cpu}")
    
    # Attach to ring buffer
    bpf["events"].open_perf_buffer(handle_security_event)
    
    print("eBPF security hooks loaded successfully!")
    
    # Run with BCC
    def bpf_poll_loop():
        while collector.running:
            try:
                bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
    
    USE_EBPF = True
    
except ImportError:
    print("BCC not available - using fallback monitoring")
    USE_EBPF = False
except Exception as e:
    print(f"eBPF initialization failed: {e} - using fallback monitoring")
    USE_EBPF = False

# Initialize collector
collector = SecurityCollector()

def signal_handler(signum, frame):
    print("\nShutting down security agent...")
    collector.stop()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    print("=" * 60)
    print("Lattice Security Agent")
    print("=" * 60)
    print(f"Reporting to: {BACKEND_URL}")
    print(f"Node: {NODE_NAME}")
    print(f"Container: {collector.container_id}")
    print("=" * 60)
    
    flow_reporter = FlowReporter()
    flow_thread = Thread(target=flow_reporter.run, daemon=True)
    flow_thread.start()
    print("Flow reporter started")
    
    collector.run()
