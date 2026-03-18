/* 
 * Lattice Security - Shared Types
 * 
 * Common type definitions and structures used across all eBPF programs.
 */

#ifndef LATTICE_TYPES_H
#define LATTICE_TYPES_H

/* Event types for security monitoring */
#define EVENT_SOCKET_CONNECT      1
#define EVENT_SECURITY_CONNECT    2
#define EVENT_SOCKET_STATE       3
#define EVENT_DNS_QUERY          4
#define EVENT_DNS_RESPONSE       5
#define EVENT_FILE_OPEN          6
#define EVENT_SENSITIVE_PATH     7
#define EVENT_BASELINE_DRIFT    8
#define EVENT_PROCESS_EXEC       9

/* Severity levels */
#define SEVERITY_INFO       0
#define SEVERITY_LOW        1
#define SEVERITY_MEDIUM     2
#define SEVERITY_HIGH       3
#define SEVERITY_CRITICAL   4

/* Connection state tracking */
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_CLOSE        7

/* Key structure for connection tracking */
struct connect_key_t {
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
    __u32 pid;
};

/* Process information stored in maps */
struct process_info_t {
    __u32 pid;
    __u32 tgid;
    __u64 timestamp;
    char comm[16];
};

/* Socket statistics counter */
struct socket_stats_t {
    __u64 total_connections;
    __u64 outbound_connections;
    __u64 inbound_connections;
    __u64 dns_queries;
    __u64 sensitive_access;
};

/* Main event structure - variable size based on event type */
struct event_t {
    __u64 timestamp;
    __u32 event_type;
    __u32 pid;
    __u32 tgid;
    
    /* Network information */
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
    __u8 family;
    __u8 protocol;
    
    /* Process information */
    char comm[16];
    
    /* Container information */
    char container_id[64];
    
    /* Severity (for security events) */
    __u8 severity;
    
    /* Path (for file access events) */
    char path[256];
    
    /* Additional details pointer (used in some events) */
    void *details;
    __u32 details_len;
};

/* DNS-specific event data */
struct dns_event_t {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    char comm[16];
    char container_id[64];
    
    /* DNS query information */
    char query[256];
    __u16 query_type;
    __u16 id;
    
    /* Response information */
    __u8 is_response;
    __u8 rcode;  /* DNS response code */
    
    /* Analysis results */
    __u8 entropy;      /* Domain entropy score */
    __u8 threat_level; /* Calculated threat level */
};

/* File access event */
struct file_event_t {
    __u64 timestamp;
    __u32 event_type;
    __u32 pid;
    __u32 tgid;
    char comm[16];
    char container_id[64];
    
    /* File path */
    char path[512];
    
    /* Operation type */
    __u32 flags;
    
    /* Access mode */
    __u32 mode;
    
    /* Risk assessment */
    __u8 risk_level;
    __u8 is_sensitive;
};

/* Baseline drift event */
struct drift_event_t {
    __u64 timestamp;
    __u32 event_type;
    __u32 pid;
    __u32 tgid;
    char comm[16];
    char container_id[64];
    char container_image[256];
    
    /* What violated the baseline */
    char violation_type[32];  /* "syscall", "path", "network" */
    char violation_detail[512];
    
    /* Baseline info */
    __u32 baseline_version;
};

/* BPF helper to get container ID from cgroup */
static inline void get_container_id(void *task, char *buf, __u32 buf_size)
{
    __u64 id;
    __u32 off;
    
    /* Try to read cgroup id from task's cgroups */
    struct cgroup *cgrp = NULL;
    
    /* Common container cgroup paths */
    const char *cgroup_paths[] = {
        "/docker/",
        "/containerd/",
        "/crio/",
        "/kubepods/",
    };
    
#pragma unroll
    for (int i = 0; i < 4; i++) {
        bpf_probe_read_user_str(buf, buf_size, cgroup_paths[i]);
        if (buf[0] != 0) {
            /* Found a match, now extract container ID */
            char *id_start = buf + __len(cgroup_paths[i]);
            int len = 0;
            while (len < 64 && id_start[len] != '\0' && id_start[len] != '/') {
                len++;
            }
            return;
        }
    }
    
    /* No container ID found - likely host process */
    buf[0] = '\0';
}

/* Calculate string entropy (Shannon entropy) */
static inline __u8 calculate_entropy(const char *str, __u32 len)
{
    /* Simple entropy calculation for DNS domain names */
    /* Returns value 0-255 representing entropy score */
    
    /* Count character frequencies */
    __u32 freq[256] = {0};
    __u32 total = 0;
    
#pragma unroll
    for (int i = 0; i < 64 && i < len; i++) {
        freq[(unsigned char)str[i]]++;
        total++;
    }
    
    if (total == 0)
        return 0;
    
    /* Calculate Shannon entropy */
    __u64 entropy = 0;
#pragma unroll
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            __u64 p = (freq[i] * 256) / total;
            entropy += (__u64)p * bpf_log2(256 / p);
        }
    }
    
    /* Return normalized entropy (0-255) */
    return (__u8)(entropy >> 8);
}

/* Check if a path matches sensitive patterns */
static inline __u8 is_sensitive_path(const char *path)
{
    /* Critical paths that indicate potential compromise */
    const char *critical_paths[] = {
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/passwd",     /* Read is normal, but combined with writes is bad */
        "/etc/kubernetes/admin.conf",
        "/etc/kubeconfig",
        "/run/secrets/",
        "/var/log/audit/",
        "/root/.ssh/",
        "/.docker/config.json",
    };
    
    /* Cloud metadata service IP */
    const __u32 METADATA_IP = 0xFEA9FEA9; /* 169.254.169.254 in network order */
    
#pragma unroll
    for (int i = 0; i < 9; i++) {
        if (bpf_strncmp(path, __len(critical_paths[i]), critical_paths[i]) == 0) {
            return 1; /* Match */
        }
    }
    
    return 0;
}

/* Check for cloud metadata IP */
static inline __u8 is_metadata_ip(__u32 ip)
{
    /* 169.254.169.254 - AWS/GCP/Azure metadata endpoint */
    __u32 metadata_ip = 0xFEA9FEA9; /* Network byte order */
    return ip == metadata_ip;
}

#endif /* LATTICE_TYPES_H */
