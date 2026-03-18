# Lattice - Kubernetes Observability Platform

A modern, scalable Kubernetes observability platform powered by eBPF that provides real-time insights into cluster health, network flows, pod status, and runtime security monitoring.

![Lattice Overview](./docs/screenshots/overview.png)

## Features

### Security View (eBPF-Powered Runtime Security)
Real-time security monitoring with intelligent threat detection:

- **Event Dashboard** - Clickable stat cards showing Total Events, Critical Alerts, High Alerts, and Baseline Drift
- **Alert Feed** - Real-time security event stream with severity-based styling
- **Runtime Drift Detection** - Baseline learning mode to capture normal behavior and detect anomalies
- **DNS Threat Analysis** - Detection of high-entropy subdomains and suspicious TLDs
- **Sensitive Path Access Monitoring** - Alerts for access to critical files like `/etc/shadow`, cloud metadata IPs, and Kubernetes secrets
- **Security Modules Overview** - Visual status of all security monitoring components

![Security View](./docs/screenshots/security-view.png)

### Grid Map (Topology View)
Visual representation of your Kubernetes cluster with:
- **Namespace-based grouping** - Pods organized by namespace for easy navigation
- **Pod restart detection** - Pods with high restart counts are highlighted with red/orange borders and "X RESTARTS" badges
- **Node mapping** - Visual connections showing which pods run on which nodes
- **Service awareness** - Different visual styling for pods vs services vs nodes

![Grid Map](./docs/screenshots/grid-map.png)

### Flow Matrix
Deep socket-level network analysis with:
- Real-time traffic flow monitoring
- Source and destination visualization
- Protocol and port tracking
- Traffic intensity metrics (packet counts)

![Flow Matrix](./docs/screenshots/flow-matrix.png)

### Overview Dashboard
- Cluster node count and health status
- Active pod statistics
- Traffic flow summary
- Recent activity stream
- Infrastructure health indicators

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     React Frontend                           │
│                   (lattice-frontend)                       │
│              Port 80 (nginx)                                 │
└─────────────────────┬───────────────────────────────────────┘
                      │ API
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   FastAPI Backend                           │
│                    (lattice-backend)                        │
│                     Port 8000                               │
│  ┌──────────────┬──────────────┬──────────────────────┐      │
│  │   Auth       │  K8s API   │   Security Events   │      │
│  │   (JWT)      │  (cluster)  │   + Baseline        │      │
│  └──────────────┴──────────────┴──────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
      ┌───────────────┼───────────────┐
      ▼               ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ Kubernetes  │ │ PostgreSQL  │ │   eBPF      │
│   API       │ │  Database   │ │   Agent     │
│  (cluster)  │ │ (lattice-db)│ │ (DaemonSet) │
└─────────────┘ └─────────────┘ └─────────────┘
```

## Components

| Component | Description |
|-----------|-------------|
| **lattice-frontend** | React application with cyberpunk UI |
| **lattice-backend** | FastAPI server providing REST API + Security monitoring |
| **lattice-db** | PostgreSQL for metric storage |
| **lattice-agent** | eBPF-based network monitoring (DaemonSet) |

## Deployment

Deploy the entire stack to the `lattice` namespace:

```bash
# Using the included Helm chart
helm install lattice ./helm/lattice --namespace lattice --create-namespace

# Or use the convenience script
./helm/install.sh
```

### Prerequisites

- Kubernetes cluster (1.20+)
- Helm 3.x
- Images pushed to your registry (update values in `helm/lattice/values.yaml`)

### Configuration

Key values in `helm/lattice/values.yaml`:

```yaml
backend:
  image: 192.168.1.20:5000/lattice-backend:v1.0.9

frontend:
  image: 192.168.1.20:5000/lattice-frontend:v1.0.7

agent:
  image: 192.168.1.20:5000/lattice-agent:v1.0.6

namespace: lattice
```

### Access the Dashboard

```bash
kubectl port-forward svc/lattice-frontend 8080:80 -n lattice
```

Then open http://localhost:8080 in your browser.

**Default credentials:**
- Username: `admin`
- Password: `change-me-admin` (or from K8s Secret `initial-admin-secret`)

## API Endpoints

### Authentication
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/token` | POST | Authenticate and get JWT token |

### Topology & Network
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/topology` | GET | Get cluster topology (pods, services, nodes) |
| `/api/flows` | GET | Get network flow data |
| `/api/report-flow` | POST | Report network flow from agent |

### Security Monitoring
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/security/events` | GET | Get security events |
| `/api/security/events` | POST | Report security event (from agent) |
| `/api/security/alerts` | GET | Get critical/high alerts |
| `/api/security/drift` | GET | Get baseline drift status |
| `/api/security/dns-threats` | GET | Get DNS threat analysis |
| `/api/security/sensitive-access` | GET | Get sensitive path access events |
| `/api/security/baseline` | GET | Get baseline learning state |
| `/api/security/baseline` | PUT | Enable/disable baseline learning mode |
| `/api/security/baseline/capture` | POST | Capture event to baseline |

## Security Features

### Learning Mode
The baseline learning mode captures normal behavior for your cluster:

1. Enable "Learning Mode" toggle in Security View
2. System captures paths and processes during learning period
3. New events are compared against the learned baseline
4. Deviations are flagged as "Baseline Drift"

### Clickable Security Stats
All four stat cards (Total Events, Critical, High Alerts, Baseline Drift) are clickable and reveal detailed views:

- **Total Events** - Full list of all security events
- **Critical** - Critical alerts requiring immediate action
- **High Alerts** - High priority alerts
- **Baseline Drift** - Container-wise drift breakdown with compliance metrics

### Security Event Types
- `SOCKET_CONNECT` - Network connection tracking
- `DNS_QUERY` - DNS query monitoring with entropy analysis
- `SENSITIVE_PATH_ACCESS` - Access to sensitive files/paths
- `BASELINE_DRIFT` - Deviation from learned baseline

## Restart Detection

The Grid Map automatically highlights pods with container restarts:

- **Red border intensity** scales with restart count
- **"X RESTARTS" badge** displays on affected pods
- Restarts are fetched from Kubernetes container status metrics

This helps operators quickly identify:
- Crashing applications
- Misconfigured pods
- Resource constraint issues
- Graceful rolling updates

## Tech Stack

- **Frontend**: React 18, Tailwind CSS, React Flow, Vite
- **Backend**: Python FastAPI, JWT authentication, Kubernetes client
- **Database**: PostgreSQL
- **Agent**: Python with eBPF (fallback to proc-based monitoring)
- **Deployment**: Helm charts

## Project Structure

```
lattice/
├── agent/              # eBPF agent code
│   ├── agent.py        # Main agent with security monitoring
│   └── Dockerfile
├── backend/            # FastAPI backend
│   ├── main.py         # Main application
│   └── Dockerfile
├── frontend/           # React frontend
│   ├── src/
│   │   └── App.jsx     # Main React component
│   ├── nginx.conf
│   └── Dockerfile
├── helm/               # Helm charts
│   └── lattice/        # Lattice Helm chart
│       ├── values.yaml
│       └── templates/
└── docs/
    └── screenshots/     # Documentation screenshots
```
