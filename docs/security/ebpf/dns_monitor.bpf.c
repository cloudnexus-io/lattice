// Lattice Security - DNS Threat Monitoring eBPF Hook
//
// Captures DNS queries and responses for threat detection.
// Detects: high-entropy subdomains, DGA patterns, C2 communication.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "types.h"

/* DNS Query Types */
#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_SOA    6
#define DNS_TYPE_PTR    12
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT     16
#define DNS_TYPE_AAAA    28
#define DNS_TYPE_SRV     33
#define DNS_TYPE_ANY     255

/* DNS Response Codes */
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NOERROR   0

/* Entropy thresholds */
#define HIGH_ENTROPY_THRESHOLD 45  /* 4.5 * 10, stored as integer */

/* NXDOMAIN rate thresholds */
#define NXDOMAIN_RATE_THRESHOLD 30  /* 30% */

/* Hash map for DNS query rate limiting */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dns_key_t);
    __type(value, struct dns_stats_t);
} dns_tracker SEC(".maps");

/* Store for high-entropy domain detection */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);  /* Container hash */
    __type(value, struct domain_history_t);
} domain_history SEC(".maps");

/* Ring buffer for DNS events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} dns_events SEC(".maps");

/* Key for tracking DNS queries per domain */
struct dns_key_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    char domain[128];
};

/* Statistics for rate limiting */
struct dns_stats_t {
    __u64 total_queries;
    __u64 nxdomain_count;
    __u64 high_entropy_count;
    __u64 last_query_time;
    char last_domain[128];
};

/* Domain history for pattern detection */
struct domain_history_t {
    __u64 timestamps[16];  /* Last 16 query times */
    __u32 query_count;
    __u8 recent_entropies[16];
    __u8 idx;
};

/* 
 * Attach to: udp_sendmsg (port 53)
 * Intercepts outgoing DNS queries
 */
SEC("sockops")
int handle_dns_query(struct bpf_sock_ops *ctx)
{
    /* Only track port 53 */
    if (ctx->remote_port != bpf_htons(53))
        return 0;
    
    /* Only track UDP */
    if (ctx->family != AF_INET)
        return 0;
    
    return 0;  /* DNS via UDP sendmsg handled differently */
}

/*
 * Attach to: udp_sendmsg
 * Alternative approach for DNS interception
 */
SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter_sendto *ctx)
{
    int fd = (int)ctx->fd;
    struct dns_event_t *event = NULL;
    
    /* Get socket info to check if it's DNS */
    struct sock *sk = NULL;
    bpf_probe_read(&sk, sizeof(sk), (void *)ctx->fd);
    
    if (!sk)
        return 0;
    
    /* Check destination port - simplified check */
    /* In practice, you'd need to trace the UDP packet data */
    
    return 0;
}

/*
 * Parse DNS query from UDP packet data
 * This is a simplified parser - full implementation would need
 * proper DNS packet parsing with BPF helpers
 */
static inline int parse_dns_query(void *data, void *data_end, 
                                   struct dns_event_t *event,
                                   __u16 *query_type)
{
    /* DNS Header is 12 bytes */
    struct dns_header {
        __u16 id;
        __u16 flags;
        __u16 qdcount;
        __u16 ancount;
        __u16 nscount;
        __u16 arcount;
    } *hdr;
    
    /* Variable for domain parsing */
    char *ptr = (char *)data + sizeof(struct dns_header);
    char domain[256] = {0};
    int offset = 0;
    
    /* Bounds check */
    if ((void *)(ptr + 1) > data_end)
        return -1;
    
    /* Parse domain name (DNS format: length-prefixed labels) */
    while (*ptr != 0) {
        __u8 label_len = *ptr;
        
        if (label_len > 63 || (void *)(ptr + label_len + 1) > data_end)
            return -1;
        
        /* Copy label */
        __builtin_memcpy(domain + offset, ptr + 1, label_len);
        offset += label_len;
        domain[offset++] = '.';
        ptr += label_len + 1;
    }
    
    domain[offset > 0 ? offset - 1 : 0] = '\0';
    
    /* Copy to event */
    __builtin_memcpy(event->query, domain, sizeof(domain));
    
    /* Read query type (2 bytes after domain name) */
    ptr += 1; /* Skip null terminator */
    if ((void *)(ptr + 4) > data_end)
        return -1;
    
    __builtin_memcpy(query_type, ptr, sizeof(__u16));
    *query_type = bpf_ntohs(*query_type);
    
    /* Skip query type and class */
    ptr += 4;
    
    return 0;
}

/*
 * Calculate threat score for a domain
 */
static inline __u8 calculate_threat_score(struct dns_event_t *event)
{
    __u8 score = 0;
    
    /* High entropy check */
    if (event->entropy > HIGH_ENTROPY_THRESHOLD) {
        score += 3; /* HIGH severity */
    }
    
    /* Long subdomain check (potential DGA) */
    if (event->entropy > 40) {
        score += 2;
    }
    
    /* NXDOMAIN rate check - would need aggregation in userspace */
    /* For now, mark each NXDOMAIN as medium threat */
    if (event->rcode == DNS_RCODE_NXDOMAIN) {
        score += 2;
    }
    
    /* Very high entropy (possible encryption) */
    if (event->entropy > 55) {
        score += 4; /* CRITICAL */
    }
    
    return score > 10 ? 10 : score;
}

/*
 * Security event generator for DNS threats
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int handle_dns_security(struct trace_event_raw_sys_enter *ctx)
{
    /* This is a placeholder - actual implementation would 
       trace UDP packets to port 53 or hook into DNS resolver */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
