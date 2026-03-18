# Lattice Security View - Implementation Plan

## Overview

This document outlines the implementation plan for adding a comprehensive "Security View" dashboard to Lattice, leveraging eBPF for real-time security monitoring within Kubernetes clusters.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Security Event Pipeline                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
            ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
            │   Socket-to-  │ │    DNS        │ │   Sensitive   │
            │   Process     │ │   Threat      │ │   Path       │
            │   Correlation │ │   Monitoring  │ │   Access     │
            └───────┬───────┘ └───────┬───────┘ └───────┬───────┘
                    │                 │                 │
                    └─────────────────┼─────────────────┘
                                      ▼
                    ┌───────────────────────────────────┐
                    │        eBPF Security Hooks        │
                    │  • tcp_v4_connect                 │
                    │  • security_socket_connect        │
                    │  • security_file_open            │
                    │  • udp_sendmsg (DNS)             │
                    │  • vfs_open                      │
                    └─────────────────┬─────────────────┘
                                      │ ringbuf/perf buffer
                                      ▼
                    ┌───────────────────────────────────┐
                    │     Go/Rust Collector Agent       │
                    │  • K8s Metadata Enrichment        │
                    │  • Process/PID Resolution         │
                    │  • Baseline Store (Drift)         │
                    │  • Event Aggregation              │
                    └─────────────────┬─────────────────┘
                                      │ gRPC/REST
                                      ▼
                    ┌───────────────────────────────────┐
                    │      FastAPI Security Backend      │
                    │  • /api/security/events           │
                    │  • /api/security/alerts           │
                    │  • /api/security/baseline        │
                    │  • /api/security/drift           │
                    └─────────────────┬─────────────────┘
                                      │
                                      ▼
                    ┌───────────────────────────────────┐
                    │      Security View Dashboard       │
                    │  • Alert Feed                     │
                    │  • Drift Status                   │
                    │  • DNS Threat Panel               │
                    │  • Sensitive Access Monitor       │
                    └───────────────────────────────────┘
```

## Module Specifications

### 1. Socket-to-Process Correlation

**Purpose**: Map network connections to their originating processes and containers.

**eBPF Hooks**:
- `tcp_v4_connect`: Captures outgoing TCP connection attempts
- `security_socket_connect`: Captures accepted incoming connections

**Data Captured**:
| Field | Type | Description |
|-------|------|-------------|
| saddr | u32 | Source IPv4 address |
| daddr | u32 | Destination IPv4 address |
| dport | u16 | Destination port |
| pid | u32 | Process ID |
| tgid | u32 | Thread Group ID |
| comm | char[16] | Process name |
| container_id | char[64] | Container ID from cgroup |

**Enrichment**:
- Kubernetes Pod Name
- Kubernetes Namespace  
- Container ID
- Container Image

### 2. Runtime Drift Detection

**Purpose**: Detect deviations from learned baseline behavior.

**Mechanism**:
1. **Baseline Learning Mode**: Capture all syscalls/file accesses during "known good" period
2. **Detection Mode**: Flag any access outside baseline

**Monitored Events**:
- Syscall patterns (sys_enter tracepoints)
- File path access (vfs_open, security_file_open)
- Network patterns

**Baseline Store Structure**:
```json
{
  "image_hash": "sha256:abc123...",
  "allowed_paths": [
    "/usr/bin/python3",
    "/etc/ssl/certs/*",
    "/var/log/*.log"
  ],
  "allowed_syscalls": ["read", "write", "open", "close", "execve"],
  "baseline_version": 1,
  "created_at": "2026-03-18T00:00:00Z"
}
```

### 3. DNS Threat Monitoring

**Purpose**: Detect C2 communication patterns via DNS analysis.

**Indicators**:
| Indicator | Threshold | Severity |
|-----------|-----------|----------|
| High-entropy subdomain | Shannon entropy > 4.5 | HIGH |
| NXDOMAIN rate | > 30% in 60s window | MEDIUM |
| Rapid DNS requests | > 100/min to same domain | HIGH |
| DGA-like patterns | Base32/hex subdomain | CRITICAL |
| Known C2 domains | Match threat intel list | CRITICAL |

**DNS Query Analysis**:
```
Domain: sub-domain.target-domain.com
├── subdomain: sub-domain (analyzed for entropy)
├── sld: target-domain
└── tld: com
```

### 4. Sensitive Path Access

**Monitored Paths**:
| Path | Risk Level | Description |
|------|------------|-------------|
| `/etc/shadow` | CRITICAL | Password hashes |
| `/etc/kubernetes/admin.conf` | CRITICAL | Admin credentials |
| `/etc/kubeconfig` | CRITICAL | Kubeconfig files |
| `169.254.169.254` | HIGH | Cloud metadata service |
| `/var/log/audit/*` | HIGH | Audit log tampering |
| `/proc/*/environ` | MEDIUM | Environment variables |
| `/run/secrets/*` | CRITICAL | Kubernetes secrets |

## Technical Implementation

### eBPF Program Structure

```
security-ebpf/
├── src/
│   ├── socket_trace.bpf.c      # Socket-to-process correlation
│   ├── dns_monitor.bpf.c       # DNS threat detection
│   ├── file_monitor.bpf.c      # Sensitive path access
│   ├── drift_detector.bpf.c     # Baseline drift detection
│   └── shared/
│       ├── maps.h              # Shared eBPF maps
│       ├── types.h             # Event structures
│       └── context.h           # K8s context helpers
├── loader/
│   └── collector.go            # Go collector
└── libbpf-wrapper/
    └── bpf_loader.c            # CO-RE loader
```

### Collector Agent Architecture

```
┌─────────────────────────────────────────┐
│           Collector Agent (Go)           │
├─────────────────────────────────────────┤
│  eBPF Loader    │  Event Processor     │
│  ────────────   │  ───────────────     │
│  • CO-RE attach │  • PID resolution     │
│  • Map updates  │  • K8s enrichment    │
│  • Ring buffer  │  • Baseline check     │
│                 │  • Alert generation   │
├─────────────────────────────────────────┤
│           Metadata Enricher              │
│  ────────────────────────────────       │
│  • /var/run/secrets/kubernetes.io/...  │
│  • cgroup info → container ID          │
│  • Containerd CRI API lookup            │
└─────────────────┬───────────────────────┘
                  │ gRPC Stream
                  ▼
┌─────────────────────────────────────────┐
│         FastAPI Security Endpoint        │
└─────────────────────────────────────────┘
```

## Data Models

### SecurityEvent
```go
type SecurityEvent struct {
    EventID      string            `json:"event_id"`
    Timestamp    time.Time        `json:"timestamp"`
    EventType   SecurityEventType `json:"event_type"`
    Severity     Severity          `json:"severity"`
    
    // Network Context
    SrcIP       string            `json:"src_ip"`
    DstIP       string            `json:"dst_ip"`
    DstPort     uint16            `json:"dst_port"`
    Protocol    string            `json:"protocol"`
    
    // Process Context
    PID         uint32            `json:"pid"`
    TGID        uint32            `json:"tgid"`
    Comm        string            `json:"comm"`
    
    // Kubernetes Context
    Namespace   string            `json:"namespace"`
    PodName    string            `json:"pod_name"`
    ContainerID string            `json:"container_id"`
    ContainerImage string        `json:"container_image"`
    
    // Event-specific Data
    Details     map[string]interface{} `json:"details"`
    
    // Drift Detection
    IsBaselineViolation bool       `json:"is_baseline_violation"`
    BaselineVersion    int        `json:"baseline_version"`
}

type SecurityEventType string
const (
    SocketConnect     SecurityEventType = "SOCKET_CONNECT"
    DNSQuery          SecurityEventType = "DNS_QUERY"
    DNSTunnel         SecurityEventType = "DNS_TUNNEL"
    SensitivePath     SecurityEventType = "SENSITIVE_PATH_ACCESS"
    BaselineDrift     SecurityEventType = "BASELINE_DRIFT"
    ProcessExec       SecurityEventType = "PROCESS_EXEC"
)

type Severity string
const (
    SeverityInfo     Severity = "INFO"
    SeverityLow      Severity = "LOW"
    SeverityMedium   Severity = "MEDIUM"
    SeverityHigh     Severity = "HIGH"
    SeverityCritical  Severity = "CRITICAL"
)
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/security/events` | GET | List security events (paginated, filterable) |
| `/api/security/events/{id}` | GET | Get specific event details |
| `/api/security/alerts` | GET | List active alerts |
| `/api/security/alerts/{id}/acknowledge` | POST | Acknowledge an alert |
| `/api/security/baseline` | GET | Get baseline for container image |
| `/api/security/baseline` | POST | Create/update baseline |
| `/api/security/baseline/{hash}/learn` | POST | Enter learning mode |
| `/api/security/drift` | GET | Get drift statistics |
| `/api/security/dns-threats` | GET | Get DNS threat indicators |
| `/api/security/sensitive-access` | GET | Get sensitive path access events |

## Performance Considerations

1. **eBPF Overhead**: Target < 1% CPU per node
2. **Ring Buffer**: Use `BPF_ringbuf` for lower overhead vs perf buffer
3. **Aggregation**: Pre-aggregate in-kernel where possible (e.g., DNS counts)
4. **Sampling**: Support configurable sampling rate for high-volume events
5. **Connection Pooling**: gRPC streams for efficient data transfer

## Security Considerations

1. **Privilege**: Requires CAP_BPF and CAP_SYS_ADMIN (or CAP_PERFMON)
2. **Container Isolation**: Agent runs as privileged DaemonSet
3. **Data Privacy**: No sensitive data (passwords, tokens) in event logs
4. **Audit Trail**: All baseline changes are logged

## Implementation Phases

### Phase 1: Foundation
- [ ] eBPF skeleton with socket correlation
- [ ] Go collector with K8s enrichment
- [ ] Basic Security Events API

### Phase 2: DNS Monitoring
- [ ] DNS query interception
- [ ] Entropy calculation
- [ ] Threat detection logic

### Phase 3: Drift Detection
- [ ] Baseline store (PostgreSQL)
- [ ] Baseline learning UI
- [ ] Drift alert generation

### Phase 4: Sensitive Path Monitoring
- [ ] File open hooks
- [ ] Cloud metadata detection
- [ ] Path-based alerting

### Phase 5: Dashboard
- [ ] Security View React component
- [ ] Alert feed
- [ ] Drift status panel
- [ ] Real-time updates (WebSocket)
