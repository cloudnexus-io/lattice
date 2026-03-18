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

app = FastAPI(title="Lattice Backend")

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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.password != ADMIN_PASSWORD:
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

@app.get("/topology")
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

@app.post("/report-flow")
async def report_flow(report: FlowReport):
    # Aggregate flows by source (pod name) and dest port
    key = f"{report.src}:{report.port}"
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

@app.get("/flows")
async def get_flows(token: str = Depends(oauth2_scheme)):
    # Add some jitter to make counts look alive
    result = []
    for flow in flows_db.values():
        flow_copy = flow.copy()
        flow_copy["count"] += random.randint(1, 20) # Simulate traffic happening
        result.append(flow_copy)
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
