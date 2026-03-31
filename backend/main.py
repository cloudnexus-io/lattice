from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import os
import uvicorn
import jwt
import datetime
import random
import threading
import time

app = FastAPI(title="Lattice Backend")

def mock_event_generator():
    """Background task to generate mock events when learning mode is enabled."""
    while True:
        try:
            if baseline_state["learning_enabled"]:
                new_event = generate_mock_security_event()
                capture_to_baseline(new_event)
                security_events_db.insert(0, new_event)
                if len(security_events_db) > 1000:
                    del security_events_db[1000:]
        except Exception as e:
            pass
        time.sleep(3)

event_thread = threading.Thread(target=mock_event_generator, daemon=True)
event_thread.start()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Secret will be retrieved from K8s Secret 'initial-admin-secret' via Env Var
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin") # Fallback for local dev
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key")
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/token")

class Token(BaseModel):
    access_token: str
    token_type: str

class FlowLog(BaseModel):
    id: int
    source_pod: str
    dest_pod: str
    protocol: str
    port: int
    timestamp: datetime.datetime

class NodeInfo(BaseModel):
    id: str
    name: str
    type: str # pod, service, node, etc.
    status: str

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

AGENT_PASSWORD = os.getenv("AGENT_PASSWORD", "lattice-agent-secret")

# In-memory user store (in production, this would be in the database)
users_db = {
    "admin": {"username": "admin", "password": "admin", "role": "admin"},
}

class UserCreate(BaseModel):
    username: str
    password: str

class UserUpdate(BaseModel):
    password: str

class UserResponse(BaseModel):
    username: str
    role: str

@app.post("/api/users", response_model=UserResponse)
async def create_user(user: UserCreate, token: str = Depends(oauth2_scheme)):
    if user.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    users_db[user.username] = {
        "username": user.username,
        "password": user.password,
        "role": "user"
    }
    return {"username": user.username, "role": "user"}

@app.get("/api/users", response_model=List[UserResponse])
async def list_users(token: str = Depends(oauth2_scheme)):
    return [{"username": u["username"], "role": u["role"]} for u in users_db.values()]

@app.delete("/api/users/{username}")
async def delete_user(username: str, token: str = Depends(oauth2_scheme)):
    if username == "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete admin user"
        )
    if username not in users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    del users_db[username]
    return {"message": "User deleted"}

@app.put("/api/users/{username}")
async def update_user(username: str, user: UserUpdate, token: str = Depends(oauth2_scheme)):
    if username not in users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    users_db[username]["password"] = user.password
    return {"message": "Password updated"}

@app.post("/api/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Check against users_db or agent password
    user = users_db.get(form_data.username)
    if not user or user.get("password") != form_data.password:
        if form_data.password != AGENT_PASSWORD:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

from kubernetes import client, config

# Load K8s config
try:
    config.load_incluster_config()
except:
    config.load_kube_config()

k8s_v1 = client.CoreV1Api()
k8s_apps = client.AppsV1Api()

# API routes - prefix all endpoints with /api
@app.get("/api/topology")
async def get_topology(token: str = Depends(oauth2_scheme)):
    nodes = []
    links = []
    
    # Get Nodes
    k8s_nodes = k8s_v1.list_node()
    for n in k8s_nodes.items:
        # Extract metrics (in a real app, you'd query metrics-server, here we use capacity/allocatable)
        cpu_capacity = n.status.capacity.get('cpu', '0')
        mem_capacity = n.status.capacity.get('memory', '0')
        
        # Calculate uptime from creation timestamp
        uptime = "Unknown"
        if n.metadata.creation_timestamp:
            delta = datetime.datetime.now(datetime.timezone.utc) - n.metadata.creation_timestamp
            days = delta.days
            hours = delta.seconds // 3600
            uptime = f"{days}d {hours}h"

        nodes.append({
            "id": n.metadata.name,
            "name": n.metadata.name,
            "type": "node",
            "status": n.status.conditions[-1].type if n.status.conditions else "Unknown",
            "metrics": {
                "cpu": cpu_capacity,
                "memory": mem_capacity,
                "uptime": uptime,
                "kernel": n.status.node_info.kernel_version,
                "os": n.status.node_info.os_image
            }
        })
        
    # Get Pods
    pods = k8s_v1.list_pod_for_all_namespaces()
    for p in pods.items:
        pod_id = f"pod-{p.metadata.name}"
        # Mock CPU/Memory/Packet data
        cpu_usage = f"{random.randint(5, 50)}m" # 5m to 50m CPU
        mem_usage = f"{random.randint(10, 200)}Mi" # 10Mi to 200Mi Memory
        packet_count = random.randint(100, 5000) # 100 to 5000 packets
        
        # Get restart count from container statuses
        restart_count = sum(cs.restart_count for cs in (p.status.container_statuses or []))
        
        nodes.append({
            "id": pod_id,
            "name": p.metadata.name,
            "type": "pod",
            "status": p.status.phase,
            "namespace": p.metadata.namespace,
            "ip": p.status.pod_ip,
            "node": p.spec.node_name,
            "metrics": {
                "cpu_usage": cpu_usage,
                "memory_usage": mem_usage,
                "packet_count": packet_count,
                "restart_count": restart_count
            }
        })
        # Link pod to node
        if p.spec.node_name:
            links.append({"source": pod_id, "target": p.spec.node_name})
            
    # Get Services
    svcs = k8s_v1.list_service_for_all_namespaces()
    for s in svcs.items:
        svc_id = f"svc-{s.metadata.name}"
        nodes.append({
            "id": svc_id,
            "name": s.metadata.name,
            "type": "service",
            "status": "Active",
            "namespace": s.metadata.namespace
        })
        
    return {"nodes": nodes, "links": links}

class FlowReport(BaseModel):
    src: str
    dst: str
    port: int
    node: str

flows_db = {} # Temporary in-memory storage keyed by port

SEED_FLOWS = [
    {"source": "nginx-abc123", "dest": "10.10.1.10", "proto": "TCP", "port": 80, "count": 150},
    {"source": "nginx-abc123", "dest": "10.10.1.11", "proto": "TCP", "port": 443, "count": 89},
    {"source": "redis-def456", "dest": "10.10.1.20", "proto": "TCP", "port": 6379, "count": 234},
    {"source": "postgres-ghi789", "dest": "10.10.1.30", "proto": "TCP", "port": 5432, "count": 67},
    {"source": "api-server-jkl012", "dest": "10.10.1.40", "proto": "TCP", "port": 8080, "count": 312},
    {"source": "api-server-jkl012", "dest": "10.10.1.50", "proto": "TCP", "port": 9090, "count": 45},
    {"source": "task-processor-mno345", "dest": "10.10.1.60", "proto": "TCP", "port": 5672, "count": 178},
]

for flow in SEED_FLOWS:
    key = f"{flow['dest']}:{flow['port']}"
    flows_db[key] = flow.copy()
    flows_db[key]["last_seen"] = datetime.datetime.utcnow().isoformat()

@app.post("/api/report-flow")
async def report_flow(report: FlowReport):
    # Aggregate flows by dest:port to match seed flows
    key = f"{report.dst}:{report.port}"
    if key in flows_db:
        flows_db[key]["count"] += random.randint(5, 50) # Increment by realistic packet count
        flows_db[key]["last_seen"] = datetime.datetime.utcnow().isoformat()
    else:
        flows_db[key] = {
            "source": report.src,
            "dest": report.dst,
            "proto": "tcp",
            "port": report.port,
            "count": random.randint(10, 100),
            "last_seen": datetime.datetime.utcnow().isoformat()
        }
    return {"status": "reported"}

@app.get("/api/flows")
async def get_flows(token: str = Depends(oauth2_scheme)):
    # Add some jitter to make counts look alive
    result = []
    for flow in flows_db.values():
        flow_copy = flow.copy()
        flow_copy["count"] += random.randint(1, 20) # Simulate traffic happening
        result.append(flow_copy)
    return result

@app.get("/api/flows/{source}/{dest}/{port}")
async def get_flow_details(source: str, dest: str, port: int, token: str = Depends(oauth2_scheme)):
    key = f"{dest}:{port}"
    if key not in flows_db:
        raise HTTPException(status_code=404, detail="Flow not found")
    
    flow = flows_db[key].copy()
    flow["count"] += random.randint(1, 20)
    
    # Generate simulated live packets
    packet_types = ["SYN", "ACK", "PSH", "FIN", "RST", "DATA"]
    protocols = ["TLSv1.3", "HTTP/1.1", "HTTP/2", "QUIC"]
    statuses = ["Success", "Retransmit", "Timeout"]
    
    live_packets = []
    for i in range(random.randint(3, 8)):
        live_packets.append({
            "seq": random.randint(1000, 9999),
            "ack": random.randint(1000, 9999),
            "len": random.randint(0, 1460),
            "type": random.choice(packet_types),
            "proto": random.choice(protocols),
            "status": random.choice(statuses),
            "ttl": random.randint(32, 128),
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
    
    return {
        "flow": flow,
        "live_packets": live_packets
    }

def is_external_ip(ip: str) -> bool:
    """Check if IP is external to the Kubernetes cluster network."""
    if not ip:
        return False
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return True
        first = int(parts[0])
        second = int(parts[1])
        # 10.0.0.0/8 - Kubernetes pods/services
        if first == 10:
            return False
        # 172.16.0.0/12 - Kubernetes services
        if first == 172 and 16 <= second <= 31:
            return False
        # 127.0.0.0/8 - Localhost
        if first == 127:
            return False
        # 169.254.0.0/16 - Link-local/metadata (suspicious!)
        if first == 169 and second == 254:
            return True  # Mark as external but flag as metadata
        # 192.168.x.x and everything else is external traffic
        return True
    except:
        return True

def get_ip_type(ip: str) -> tuple:
    """Determine type and service for an IP."""
    if not ip:
        return ("unknown", ip)
    
    # Cloud metadata detection
    if ip.startswith("169.254."):
        return ("metadata", "Cloud Metadata Service")
    
    # DNS servers
    if ip in ["8.8.8.8", "8.8.4.4"]:
        return ("dns", "Google DNS")
    if ip in ["1.1.1.1", "1.0.0.1"]:
        return ("dns", "Cloudflare DNS")
    if ip in ["9.9.9.9"]:
        return ("dns", "Quad9 DNS")
    
    # GitHub
    if "140.82." in ip or "140.85." in ip:
        return ("git_repo", "GitHub")
    if "192.30.252." in ip:
        return ("git_repo", "GitHub")
    
    # Docker Hub
    if "3.216." in ip or "52.72." in ip or "54.157." in ip or "52.54." in ip or "18.164." in ip:
        return ("container_registry", "Docker Hub")
    
    # GHCR
    if "140.82.11" in ip or "140.82.12" in ip or "140.82.113" in ip or "140.82.114" in ip or "140.82.115" in ip:
        return ("container_registry", "GitHub Container Registry")
    
    # Quay
    if "52.202." in ip or "52.54." in ip:
        return ("container_registry", "Quay")
    
    # Prometheus/Grafana repos
    if "199.232." in ip or "185.199." in ip:
        return ("helm_repo", "GitHub Pages (Helm Charts)")
    
    return ("external", "Unknown External Service")

@app.get("/api/global-traffic")
async def get_global_traffic(token: str = Depends(oauth2_scheme)):
    result = []
    seen_ips = {}
    
    for key, flow in flows_db.items():
        dest_ip = flow.get("dest", "")
        if is_external_ip(dest_ip):
            if dest_ip in seen_ips:
                seen_ips[dest_ip]["count"] += flow.get("count", 0)
                seen_ips[dest_ip]["bytes_out"] += flow.get("count", 0) * random.randint(100, 1500)
                seen_ips[dest_ip]["packets"] += random.randint(1, 10)
            else:
                ip_type, service = get_ip_type(dest_ip)
                seen_ips[dest_ip] = {
                    "ip": dest_ip,
                    "hostname": dest_ip,
                    "location": "EXTERNAL",
                    "type": ip_type,
                    "port": flow.get("port", 0),
                    "protocol": flow.get("proto", "TCP").upper(),
                    "service": service,
                    "count": flow.get("count", 0),
                    "bytes_in": random.randint(1000, 50000),
                    "bytes_out": flow.get("count", 0) * random.randint(100, 1500),
                    "packets": random.randint(10, 500),
                    "latency_ms": random.randint(15, 200),
                    "status": "active",
                    "source_pods": [flow.get("source", "unknown")],
                }
    
    result = list(seen_ips.values())
    
    if not result:
        result.append({
            "ip": "0.0.0.0",
            "hostname": "No external connections detected",
            "location": "N/A",
            "type": "none",
            "port": 0,
            "protocol": "N/A",
            "service": "eBPF discovering connections...",
            "count": 0,
            "bytes_in": 0,
            "bytes_out": 0,
            "packets": 0,
            "latency_ms": 0,
            "status": "idle",
            "source_pods": [],
        })
    
    return result

@app.get("/api/pods/{namespace}/{name}/events")
async def get_pod_events(namespace: str, name: str, token: str = Depends(oauth2_scheme)):
    try:
        events = k8s_v1.list_namespaced_event(namespace, field_selector=f"involvedObject.name={name}")
        return {"events": [k8s_v1.api_client.sanitize_for_serialization(e) for e in events.items]}
    except Exception as e:
        print(f"Error fetching events for {namespace}/{name}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

@app.get("/api/pods/{namespace}/{name}")
async def get_pod_manifest(namespace: str, name: str, token: str = Depends(oauth2_scheme)):
    try:
        pod = k8s_v1.read_namespaced_pod(name, namespace)
        return k8s_v1.api_client.sanitize_for_serialization(pod)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Pod not found: {str(e)}")

# Security Event Models
class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    severity: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    pid: Optional[int] = None
    tgid: Optional[int] = None
    comm: Optional[str] = None
    namespace: Optional[str] = None
    pod_name: Optional[str] = None
    container_id: Optional[str] = None
    container_image: Optional[str] = None
    path: Optional[str] = None
    details: Optional[dict] = None
    is_baseline_violation: bool = False

class DriftData(BaseModel):
    total_drifts: int
    baseline_compliance: int
    containers: list

class DNSThreat(BaseModel):
    high_entropy: int
    nxdomain_rate: int
    suspicious_tlds: int
    recent: list

class SensitiveAccess(BaseModel):
    events: list

# Mock security data generator
SECURITY_SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SECURITY_EVENT_TYPES = ["SOCKET_CONNECT", "DNS_QUERY", "SENSITIVE_PATH_ACCESS", "BASELINE_DRIFT", "DNS_TUNNEL"]
CONTAINER_IMAGES = [
    "nginx:latest",
    "redis:7-alpine",
    "postgres:15",
    "grafana:10.0",
    "prometheus:v2.45"
]
NAMESPACES = ["default", "monitoring", "kube-system", "lattice", "argocd"]
PODS = ["nginx-abc123", "redis-def456", "postgres-ghi789", "grafana-jkl012"]

def generate_mock_security_event():
    event_type = random.choice(SECURITY_EVENT_TYPES)
    severity = random.choice(SECURITY_SEVERITIES)
    
    base_event = {
        "event_id": f"sec-{random.randint(10000, 99999)}",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "event_type": event_type,
        "severity": severity,
        "namespace": random.choice(NAMESPACES),
        "pod_name": random.choice(PODS),
        "container_id": f"container{random.randint(1000,9999)}",
        "container_image": random.choice(CONTAINER_IMAGES),
        "pid": random.randint(1000, 65535),
        "tgid": random.randint(1000, 65535),
        "comm": random.choice(["python", "nginx", "postgres", "redis-server", "java"]),
        "is_baseline_violation": severity in ["HIGH", "CRITICAL"]
    }
    
    if event_type == "SOCKET_CONNECT":
        base_event["src_ip"] = f"10.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        base_event["dst_ip"] = f"10.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        base_event["dst_port"] = random.choice([80, 443, 8080, 5432, 6379])
        base_event["protocol"] = "TCP"
        base_event["comm"] = random.choice(["python", "nginx", "postgres", "redis", "java", "node"])
    elif event_type == "DNS_QUERY":
        base_event["dst_ip"] = "8.8.8.8"
        base_event["dst_port"] = 53
        base_event["protocol"] = "UDP"
        base_event["comm"] = random.choice(["systemd-resolved", " NetworkManager", "dnsmasq"])
        base_event["details"] = {
            "query": f"api-{random.randint(1000,9999)}.malicious-domain.com",
            "entropy": random.randint(45, 70),
            "threat": "HIGH_ENTROPY_SUBDOMAIN"
        }
    elif event_type == "SENSITIVE_PATH_ACCESS":
        base_event["path"] = random.choice([
            "/etc/shadow",
            "/run/secrets/kubernetes.io/serviceaccount/token",
            "169.254.169.254/latest/meta-data/",
            "/etc/sudoers",
            "/root/.ssh/authorized_keys"
        ])
        base_event["comm"] = random.choice(["python", "bash", "cat", "curl", "wget"])
        base_event["severity"] = "CRITICAL"
    elif event_type == "BASELINE_DRIFT":
        base_event["comm"] = random.choice(["python", "bash", "sh"])
        base_event["details"] = {
            "violation_type": random.choice(["syscall", "path", "network"]),
            "violation_detail": "Access to unlisted file path /tmp/malicious-binary"
        }
    
    return base_event

# Generate initial mock security events
initial_events = [generate_mock_security_event() for _ in range(random.randint(5, 15))]

# Baseline state must be defined before use
baseline_state = {
    "learning_enabled": False,
    "learning_start_time": None,
    "baseline_paths": [],
    "baseline_processes": [],
}

def capture_to_baseline(event):
    global baseline_state
    if baseline_state["learning_enabled"]:
        if event.get("path") and event["path"] not in baseline_state["baseline_paths"]:
            baseline_state["baseline_paths"].append(event["path"])
        if event.get("comm") and event["comm"] not in baseline_state["baseline_processes"]:
            baseline_state["baseline_processes"].append(event["comm"])

for event in initial_events:
    capture_to_baseline(event)
security_events_db = initial_events

@app.get("/api/security/events")
async def get_security_events(
    limit: int = 50,
    severity: Optional[str] = None,
    token: str = Depends(oauth2_scheme)
):
    events = security_events_db.copy()
    if severity:
        events = [e for e in events if e["severity"] == severity.upper()]
    return {"events": events[:limit]}

@app.get("/api/security/alerts")
async def get_security_alerts(token: str = Depends(oauth2_scheme)):
    alerts = [e for e in security_events_db if e["severity"] in ["HIGH", "CRITICAL"]]
    return {"alerts": alerts, "total": len(alerts)}

@app.get("/api/security/drift")
async def get_drift_status(token: str = Depends(oauth2_scheme)):
    total_violations = sum(1 for e in security_events_db if e.get("is_baseline_violation"))
    return {
        "total_drifts": total_violations,
        "baseline_compliance": max(50, 100 - (total_violations * 5)),
        "containers": [
            {"name": "task-processor-abc123", "violations": random.randint(0, 10), "accesses": 100},
            {"name": "redis-def456", "violations": random.randint(0, 5), "accesses": 100},
            {"name": "postgres-ghi789", "violations": random.randint(0, 3), "accesses": 100},
        ]
    }

@app.get("/api/security/dns-threats")
async def get_dns_threats(token: str = Depends(oauth2_scheme)):
    dns_events = [e for e in security_events_db if e["event_type"] == "DNS_QUERY"]
    return {
        "high_entropy": len([e for e in dns_events if e.get("details", {}).get("entropy", 0) > 45]),
        "nxdomain_rate": random.randint(5, 30),
        "suspicious_tlds": random.randint(0, 5),
        "recent": dns_events[:5] if dns_events else []
    }

@app.get("/api/security/sensitive-access")
async def get_sensitive_access(token: str = Depends(oauth2_scheme)):
    sensitive_events = [e for e in security_events_db if e["event_type"] == "SENSITIVE_PATH_ACCESS"]
    return {"events": sensitive_events}

@app.post("/api/security/events")
async def report_security_event(event: SecurityEvent, token: str = Depends(oauth2_scheme)):
    global security_events_db, baseline_state
    event_dict = event.dict()
    event_dict["event_id"] = f"sec-{random.randint(100000, 999999)}"
    event_dict["timestamp"] = datetime.datetime.utcnow().isoformat()
    security_events_db.insert(0, event_dict)
    if len(security_events_db) > 1000:
        del security_events_db[1000:]
    
    if baseline_state["learning_enabled"]:
        if event.path and event.path not in baseline_state["baseline_paths"]:
            baseline_state["baseline_paths"].append(event.path)
        if event.comm and event.comm not in baseline_state["baseline_processes"]:
            baseline_state["baseline_processes"].append(event.comm)
    
    return {"status": "recorded", "event_id": event_dict["event_id"], "captured": baseline_state["learning_enabled"]}

class BaselineConfig(BaseModel):
    learning_enabled: bool
    learning_start_time: Optional[str] = None

@app.get("/api/security/baseline")
async def get_baseline_config(token: str = Depends(oauth2_scheme)):
    return {
        "learning_enabled": baseline_state["learning_enabled"],
        "learning_start_time": baseline_state.get("learning_start_time"),
        "paths_captured": len(baseline_state["baseline_paths"]),
        "processes_captured": len(baseline_state["baseline_processes"]),
        "baseline_paths": baseline_state["baseline_paths"][-10:] if baseline_state["baseline_paths"] else [],
        "baseline_processes": baseline_state["baseline_processes"][-10:] if baseline_state["baseline_processes"] else [],
        "status": "learning" if baseline_state["learning_enabled"] else "inactive",
    }

@app.put("/api/security/baseline")
async def update_baseline_config(config: BaselineConfig, token: str = Depends(oauth2_scheme)):
    global baseline_state
    now = datetime.datetime.utcnow().isoformat()
    
    if config.learning_enabled and not baseline_state["learning_enabled"]:
        baseline_state["learning_enabled"] = True
        baseline_state["learning_start_time"] = now
        baseline_state["baseline_paths"] = []
        baseline_state["baseline_processes"] = []
        print(f"Baseline learning ENABLED at {now}")
    elif not config.learning_enabled and baseline_state["learning_enabled"]:
        baseline_state["learning_enabled"] = False
        print(f"Baseline learning DISABLED. Captured {len(baseline_state['baseline_paths'])} paths, {len(baseline_state['baseline_processes'])} processes")
    
    return {
        "status": "updated",
        "learning_enabled": baseline_state["learning_enabled"],
        "learning_start_time": baseline_state.get("learning_start_time"),
    }

@app.post("/api/security/baseline/capture")
async def capture_baseline_event(event: dict, token: str = Depends(oauth2_scheme)):
    global baseline_state
    if not baseline_state["learning_enabled"]:
        return {"status": "ignored", "reason": "learning not enabled"}
    
    if "path" in event and event["path"]:
        if event["path"] not in baseline_state["baseline_paths"]:
            baseline_state["baseline_paths"].append(event["path"])
    
    if "comm" in event and event["comm"]:
        if event["comm"] not in baseline_state["baseline_processes"]:
            baseline_state["baseline_processes"].append(event["comm"])
    
    return {"status": "captured"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
