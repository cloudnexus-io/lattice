/* Lattice Security - eBPF Security Hooks
 * 
 * This file contains eBPF programs for real-time security monitoring:
 * - Socket-to-Process Correlation
 * - DNS Threat Detection  
 * - Sensitive Path Access Monitoring
 * - Runtime Drift Detection
 * 
 * Build: clang -target bpf -O2 -c security_hooks.bpf.c
 * Requires: kernel headers, libbpf
 */

#include <uapi/linux/ptrace.h>
#include <uapi/linux/uio.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/nsproxy.h>
#include <linux/magic.h>
#include <linux/cgroup.h>

/* Event types */
#define EVENT_SOCKET_CONNECT     1
#define EVENT_DNS_QUERY         2
#define EVENT_FILE_OPEN         3
#define EVENT_SENSITIVE_PATH    4
#define EVENT_PROCESS_EXEC      5

/* Severity levels */
#define SEVERITY_INFO      0
#define SEVERITY_LOW       1
#define SEVERITY_MEDIUM    2
#define SEVERITY_HIGH      3
#define SEVERITY_CRITICAL  4

/* Maximum string lengths */
#define MAX_PATH_LEN     256
#define MAX_COMM_LEN     16
#define MAX_CONTAINER_ID 64

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Connection tracker for socket correlation */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_id_t);
    __type(value, struct process_ctx_t);
} conn_tracker SEC(".maps");

/* DNS query rate limiter */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct dns_stats_t);
} dns_tracker SEC(".maps");

/* Key for connection tracking */
struct conn_id_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

/* Process context */
struct process_ctx_t {
    __u32 pid;
    __u32 tgid;
    __u64 timestamp;
    char comm[MAX_COMM_LEN];
    char container_id[MAX_CONTAINER_ID];
};

/* DNS statistics */
struct dns_stats_t {
    __u64 total_queries;
    __u64 nxdomain_count;
    __u64 last_query_time;
    char last_domain[128];
};

/* Security event structure */
struct security_event_t {
    __u64 timestamp;
    __u32 event_type;
    __u32 pid;
    __u32 tgid;
    
    /* Network info */
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    
    /* Process info */
    char comm[MAX_COMM_LEN];
    
    /* Container info */
    char container_id[MAX_CONTAINER_ID];
    
    /* Severity and details */
    __u8 severity;
    char path[MAX_PATH_LEN];
    __u32 details_len;
};

/* Helper to get container ID from cgroup */
static __always_inline int get_container_id(struct task_struct *task, char *buf, int buf_size) {
    struct cgroup *cgrp = NULL;
    struct css_set *cgroups = task->cgroups;
    int i;
    
    if (!cgroups)
        return -1;
    
    rcu_read_lock();
    cgrp = cgroups->dfl_cgrp;
    if (!cgrp)
        goto out;
    
    /* Check for container cgroup paths */
    struct cgroup_subsys_state *css;
    cgroup_for_each_descendant_pre(css, cgrp) {
        struct cgroup *sub = css->cgroup;
        if (!sub)
            continue;
            
        /* Look for docker/containerd/crio cgroup markers */
        if (sub->kn) {
            char cgrp_path[128];
            bpf_probe_read_str(cgrp_path, sizeof(cgrp_path), (void *)sub->kn->name);
            
            /* Check for container markers */
            if (bpf_strncmp(cgrp_path, 7, "/docker") == 0 ||
                bpf_strncmp(cgrp_path, 11, "/containerd") == 0 ||
                bpf_strncmp(cgrp_path, 6, "/crio") == 0 ||
                bpf_strncmp(cgrp_path, 10, "/kubepods") == 0) {
                
                bpf_probe_read_str(buf, buf_size, cgrp_path);
                rcu_read_unlock();
                return 0;
            }
        }
    }
    
out:
    rcu_read_unlock();
    buf[0] = '\0';
    return -1;
}

/* Calculate string entropy for DNS analysis */
static __always_inline __u8 calculate_entropy(const char *str, int len) {
    __u32 freq[256] = {0};
    __u32 total = 0;
    __u64 entropy = 0;
    int i;
    
    #pragma unroll
    for (i = 0; i < 64 && i < len; i++) {
        unsigned char c = str[i];
        if (c == 0) break;
        freq[c]++;
        total++;
    }
    
    if (total == 0) return 0;
    
    #pragma unroll
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            __u64 p = (freq[i] * 256) / total;
            if (p > 0) {
                entropy += p * (8 - __builtin_clzll(p));
            }
        }
    }
    
    /* Normalize to 0-100 scale */
    return (__u8)((entropy * 100) / (total * 8));
}

/* Check if IP is cloud metadata service */
static __always_inline int is_metadata_ip(__u32 ip) {
    /* 169.254.169.254 - AWS/GCP/Azure metadata */
    __u32 metadata_ip = 0xFEA9FEA9;
    return ip == metadata_ip;
}

/* Check if path is sensitive */
static __always_inline int is_sensitive_path(const char *path) {
    /* Critical files that indicate potential compromise */
    
    /* /etc/shadow - password hashes */
    if (bpf_strncmp(path, 11, "/etc/shadow") == 0)
        return SEVERITY_CRITICAL;
    
    /* Kubernetes credentials */
    if (bpf_strncmp(path, 24, "/etc/kubernetes/admin.conf") == 0)
        return SEVERITY_CRITICAL;
    
    /* Secrets directory */
    if (bpf_strncmp(path, 14, "/run/secrets/") == 0)
        return SEVERITY_CRITICAL;
    
    /* SSH keys */
    if (bpf_strncmp(path, 10, "/root/.ssh") == 0)
        return SEVERITY_CRITICAL;
    
    /* Docker config with credentials */
    if (bpf_strncmp(path, 18, "/.docker/config.json") == 0)
        return SEVERITY_CRITICAL;
    
    /* Audit logs */
    if (bpf_strncmp(path, 16, "/var/log/audit/") == 0)
        return SEVERITY_HIGH;
    
    return 0;
}

/* Hook: TCP connect - Socket to Process Correlation */
SEC("tracepoint/tcp/tcp_v4_connect")
int handle_tcp_v4_connect(struct trace_event_raw_tcp_connect *ctx) {
    struct sock *sk = (struct sock *)ctx->sk;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    /* Get PID/TGID */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    /* Reserve ring buffer space */
    struct security_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    /* Basic event info */
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = EVENT_SOCKET_CONNECT;
    event->pid = pid;
    event->tgid = tgid;
    event->protocol = IPPROTO_TCP;
    
    /* Get process name */
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    /* Get addresses */
    event->saddr = BPF_CORE_READ(sk, sk_rcv_saddr);
    
    /* Destination from sockaddr */
    struct sockaddr_in *addr = (struct sockaddr_in *)ctx->uaddr;
    if (addr) {
        event->daddr = addr->sin_addr.s_addr;
        event->dport = bpf_ntohs(addr->sin_port);
    }
    
    /* Check for metadata IP access - CRITICAL */
    if (is_metadata_ip(event->daddr)) {
        event->severity = SEVERITY_CRITICAL;
    } else {
        event->severity = SEVERITY_LOW;
    }
    
    /* Get container ID */
    get_container_id(task, event->container_id, sizeof(event->container_id));
    
    /* Track connection for later correlation */
    struct conn_id_t conn_id = {
        .saddr = event->saddr,
        .daddr = event->daddr,
        .sport = BPF_CORE_READ(sk, sk_num),
        .dport = event->dport
    };
    
    struct process_ctx_t ctx_data = {
        .pid = pid,
        .tgid = tgid,
        .timestamp = event->timestamp
    };
    __builtin_memcpy(ctx_data.comm, event->comm, sizeof(event->comm));
    __builtin_memcpy(ctx_data.container_id, event->container_id, sizeof(event->container_id));
    
    bpf_map_update_elem(&conn_tracker, &conn_id, &ctx_data, BPF_ANY);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Hook: Security socket bind - Detect unauthorized binds */
SEC("tracepoint/socket/socket_bind")
int handle_socket_bind(struct trace_event_raw_socket_bind *ctx) {
    struct sock *sk = (struct sock *)ctx->sk;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    /* Only track interesting ports (low ports require root) */
    if (ctx->protocol->sin_port > __constant_htons(1024))
        return 0;
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct security_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = EVENT_SOCKET_CONNECT;
    event->pid = pid;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->dport = bpf_ntohs(ctx->protocol->sin_port);
    event->severity = SEVERITY_MEDIUM;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_container_id(task, event->container_id, sizeof(event->container_id));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Hook: File open - Sensitive path access */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_file_open(struct trace_event_raw_sys_enter_openat *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char path[MAX_PATH_LEN];
    
    /* Read the file path */
    bpf_probe_read_user_str(path, sizeof(path), (void *)ctx->name);
    
    /* Check if it's a sensitive path */
    int severity = is_sensitive_path(path);
    if (severity > 0) {
        struct security_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event)
            return 0;
        
        event->timestamp = bpf_ktime_get_ns();
        event->event_type = EVENT_SENSITIVE_PATH;
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        event->severity = severity;
        
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        get_container_id(task, event->container_id, sizeof(event->container_id));
        
        __builtin_memcpy(event->path, path, sizeof(event->path));
        
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Hook: Process execution - Detect execve */
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char filename[MAX_PATH_LEN];
    
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)ctx->filename);
    
    /* Check for suspicious executables */
    int is_suspicious = 0;
    
    /* wget/curl downloading and executing */
    if (bpf_strncmp(filename + bpf_strlen(filename) - 4, 4, ".sh") == 0)
        is_suspicious = 1;
    
    /* Binary from /tmp */
    if (bpf_strncmp(filename, 4, "/tmp") == 0)
        is_suspicious = 1;
    
    /* From /dev/shm */
    if (bpf_strncmp(filename, 8, "/dev/shm") == 0)
        is_suspicious = 1;
    
    if (is_suspicious) {
        struct security_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event)
            return 0;
        
        event->timestamp = bpf_ktime_get_ns();
        event->event_type = EVENT_PROCESS_EXEC;
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        event->severity = SEVERITY_HIGH;
        
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        get_container_id(task, event->container_id, sizeof(event->container_id));
        
        __builtin_memcpy(event->path, filename, sizeof(event->path));
        
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

/* Hook: UDP send - DNS Query detection */
SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_dns_query(struct trace_event_raw_sys_enter_sendto *ctx) {
    int fd = (int)ctx->fd;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    /* We'd need to trace the socket to get port - simplified here */
    /* In production, hook into inet_sendmsg or similar */
    
    return 0;
}

/* Hook: VFS open - Alternative file access hook */
SEC("kprobe/vfs_open")
int handle_vfs_open(struct pt_regs *ctx) {
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    struct qstr dname;
    char path_str[MAX_PATH_LEN];
    
    bpf_probe_read(&dname, sizeof(dname), &path->dentry->d_name);
    bpf_probe_read_str(path_str, sizeof(path_str), dname.name);
    
    int severity = is_sensitive_path(path_str);
    if (severity > 0) {
        struct security_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event)
            return 0;
        
        event->timestamp = bpf_ktime_get_ns();
        event->event_type = EVENT_FILE_OPEN;
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->severity = severity;
        
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        get_container_id(task, event->container_id, sizeof(event->container_id));
        
        __builtin_memcpy(event->path, path_str, sizeof(event->path));
        
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
