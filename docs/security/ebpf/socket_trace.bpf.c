/* 
 * Lattice Security - Socket-to-Process Correlation
 * 
 * Captures TCP connection events and correlates them with process information.
 * Uses CO-RE (Compile Once - Run Everywhere) for kernel portability.
 * 
 * License: GPL-2.0
 * Author: Lattice Security Team
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "types.h"
#include "maps.h"

/* Maximum number of entries in the connection tracking map */
#define MAX_CONNECTIONS 65536

/* Hash map to track connection attempts for correlation */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct connect_key_t);
    __type(value, struct process_info_t);
} connect_tracker SEC(".maps");

/* Ring buffer for sending events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} events SEC(".maps");

/* Counter map for socket statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct socket_stats_t);
} socket_stats SEC(".maps");

/*
 * Attach to: tcp_v4_connect
 * Triggered when a process initiates an outbound TCP connection
 */
SEC("tracepoint/tcp/tcp_v4_connect")
int handle_tcp_v4_connect(struct trace_event_raw_tcp_connect *ctx)
{
    struct sock *sk = (struct sock *)ctx->sk;
    struct event_t *event = NULL;
    
    /* Get task/process information */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if (!event)
        return 0;
    
    /* Populate event structure */
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = EVENT_SOCKET_CONNECT;
    event->pid = pid;
    event->tgid = tgid;
    
    /* Get process name */
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    /* Extract socket information */
    event->family = AF_INET;
    event->protocol = IPPROTO_TCP;
    
    /* Source address - from sk->sk_rcv_saddr */
    event->saddr = BPF_CORE_READ(sk, sk_rcv_saddr);
    
    /* Destination address - from sockaddr_in */
    struct sockaddr_in *addr = (struct sockaddr_in *)ctx->uaddr;
    if (addr) {
        event->daddr = addr->sin_addr.s_addr;
        event->dport = bpf_ntohs(addr->sin_port);
    }
    
    /* Get container ID from cgroup */
    get_container_id(task, event->container_id, sizeof(event->container_id));
    
    /* Update connection tracker for correlation with accept */
    struct connect_key_t key = {
        .saddr = event->saddr,
        .daddr = event->daddr,
        .dport = event->dport,
        .pid = pid
    };
    
    struct process_info_t pinfo = {
        .pid = pid,
        .tgid = tgid,
        .timestamp = event->timestamp
    };
    bpf_core_read_strcpy(pinfo.comm, sizeof(pinfo.comm), event->comm);
    
    bpf_map_update_elem(&connect_tracker, &key, &pinfo, BPF_ANY);
    
    /* Submit event */
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

/*
 * Attach to: security_socket_connect (kernel 5.8+)
 * Captures both inbound and outbound connection attempts
 */
SEC("tracepoint/sockets/security_socket_connect")
int handle_security_socket_connect(struct trace_event_raw_security_socket_connect *ctx)
{
    struct event_t *event = NULL;
    struct sock *sk = (struct sock *)ctx->sk;
    struct sockaddr *addr = (struct sockaddr *)ctx->uaddr;
    
    /* Only track TCP connections */
    int family = BPF_CORE_READ(sk, sk_family);
    if (family != AF_INET)
        return 0;
    
    /* Reserve ring buffer space */
    event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if (!event)
        return 0;
    
    /* Basic event info */
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = EVENT_SECURITY_CONNECT;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->family = family;
    event->protocol = BPF_CORE_READ(sk, sk_protocol);
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    /* Parse destination from sockaddr_in */
    if (addr) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        event->daddr = addr_in->sin_addr.s_addr;
        event->dport = bpf_ntohs(addr_in->sin_port);
    }
    
    /* Source address from socket */
    event->saddr = BPF_CORE_READ(sk, sk_rcv_saddr);
    
    /* Get container ID */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    get_container_id(task, event->container_id, sizeof(event->container_id));
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

/*
 * Attach to: sock:inet_sock_set_state
 * Track connection state changes for lifecycle management
 */
SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    /* Only track TCP connections */
    if (ctx->protocol != IPPROTO_TCP)
        return 0;
    
    struct event_t *event = NULL;
    
    event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = EVENT_SOCKET_STATE;
    event->protocol = IPPROTO_TCP;
    
    /* Extract addresses from the socket pointer */
    struct sock *sk = (struct sock *)ctx->sk;
    event->saddr = BPF_CORE_READ(sk, sk_rcv_saddr);
    event->daddr = BPF_CORE_READ(sk, sk_daddr);
    event->dport = BPF_CORE_READ(sk, sk_dport);
    
    /* Record old and new states */
    event->details = (void *)ctx;
    event->details_len = sizeof(struct event_t); /* Reuse for state info */
    
    /* State change tracking for connection lifecycle */
    if (ctx->newstate == TCP_SYN_SENT) {
        /* Connection initiated */
    } else if (ctx->newstate == TCP_ESTABLISHED) {
        /* Connection established - check against tracker */
        struct connect_key_t key = {
            .saddr = event->saddr,
            .daddr = event->daddr,
            .dport = event->dport
        };
        
        struct process_info_t *pinfo = bpf_map_lookup_elem(&connect_tracker, &key);
        if (pinfo) {
            event->pid = pinfo->pid;
            event->tgid = pinfo->tgid;
            bpf_core_read_strcpy(event->comm, sizeof(event->comm), pinfo->comm);
            
            /* Remove from tracker to free space */
            bpf_map_delete_elem(&connect_tracker, &key);
        }
    } else if (ctx->newstate == TCP_CLOSE) {
        /* Connection closed */
    }
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

/* Update statistics counter */
static inline void update_stats(__u32 key, __u8 event_type)
{
    struct socket_stats_t *stats = bpf_map_lookup_elem(&socket_stats, &key);
    if (stats) {
        stats->total_connections++;
        if (event_type == EVENT_SOCKET_CONNECT)
            stats->outbound_connections++;
        else
            stats->inbound_connections++;
    } else {
        struct socket_stats_t new_stats = {};
        new_stats.total_connections = 1;
        if (event_type == EVENT_SOCKET_CONNECT)
            new_stats.outbound_connections = 1;
        bpf_map_update_elem(&socket_stats, &key, &new_stats, BPF_ANY);
    }
}

char LICENSE[] SEC("license") = "GPL";
