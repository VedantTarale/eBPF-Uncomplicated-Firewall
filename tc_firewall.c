#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ALLOWED_IP_PORT_PAIRS 1024
#define MAX_EGRESS_PORTS 1024

#define EGRESS 1
#define INGRESS 2
#define INGRESS_AND_EGRESS 3

struct ip_port_key {
    __u32 ip;     
    __u16 port;      
};

// Map to store allowed IP addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWED_IP_PORT_PAIRS);
    __type(key, struct ip_port_key);
    __type(value, __u32);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} allowed_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EGRESS_PORTS);
    __type(key, __u16);
    __type(value, __u32);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} disabled_egress SEC(".maps");

static inline int parse_ipv4(void *data, void *data_end, struct iphdr **ip_hdr) {
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    *ip_hdr = (struct iphdr *)(eth + 1);
    
    if ((void *)(*ip_hdr + 1) > data_end)
        return -1;
    
    return 0;
}

static inline int is_ip_port_allowed(__u32 ip, __u16 port) {
    struct ip_port_key key = {};
    key.ip = ip;
    key.port = port;
    
    __u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &key);
    return allowed ? 1 : 0;
}

static inline int is_egress_allowed(__u16 port) {
    __u8 *allowed = bpf_map_lookup_elem(&disabled_egress, &port);
    return allowed ? 0 : 1;
}

SEC("classifier/ingress")
int tc_ingress_firewall(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *ip_hdr;
    
    if (parse_ipv4(data, data_end, &ip_hdr) < 0) {
        return TC_ACT_OK;
    }
    
    __u32 src_ip = ip_hdr->saddr;
    
    // Handle TCP or UDP
    if (ip_hdr->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = (struct tcphdr *)((void *)ip_hdr + (ip_hdr->ihl * 4));
        
        if ((void *)(tcp_hdr + 1) > data_end)
            return TC_ACT_SHOT;
            
        if (!is_ip_port_allowed(src_ip, tcp_hdr->dest)) {
            return TC_ACT_SHOT;
        }
    } else if (ip_hdr->protocol == IPPROTO_UDP) {
        struct udphdr *udp_hdr = (struct udphdr *)((void *)ip_hdr + (ip_hdr->ihl * 4));
        
        if ((void *)(udp_hdr + 1) > data_end)
            return TC_ACT_SHOT;
        
        if (!is_ip_port_allowed(src_ip, udp_hdr->dest)) {
            return TC_ACT_SHOT;
        }
    } else {
        return TC_ACT_SHOT;
    }
    
    return TC_ACT_OK;
}

SEC("classifier/egress")
int tc_egress_firewall(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *ip_hdr;
    
    if (parse_ipv4(data, data_end, &ip_hdr) < 0) {
        return TC_ACT_OK;
    }
        
    // Handle TCP or UDP
    if (ip_hdr->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = (struct tcphdr *)((void *)ip_hdr + (ip_hdr->ihl * 4));
        
        if ((void *)(tcp_hdr + 1) > data_end)
            return TC_ACT_SHOT;
            
        if (!is_egress_allowed(tcp_hdr->source)) {
            return TC_ACT_SHOT;
        }
    } else if (ip_hdr->protocol == IPPROTO_UDP) {
        struct udphdr *udp_hdr = (struct udphdr *)((void *)ip_hdr + (ip_hdr->ihl * 4));
        
        if ((void *)(udp_hdr + 1) > data_end)
            return TC_ACT_SHOT;
        
        if (!is_egress_allowed(udp_hdr->source)) {
            return TC_ACT_SHOT;
        }
    } else {
        return TC_ACT_SHOT;
    }
    
    return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";