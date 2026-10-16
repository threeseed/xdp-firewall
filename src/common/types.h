#pragma once

#include <common/int_types.h>

struct filter_ip
{
    u32 src_ip;
    u8 src_cidr;

    u32 dst_ip;
    u8 dst_cidr;

#ifdef ENABLE_IPV6
    // IPv6 addresses in network byte order (the 16 raw address bytes).
    // An address is considered set when any of its four words is non-zero.
    u32 src_ip6[4];
    u32 dst_ip6[4];
#endif

    unsigned int do_min_ttl : 1;
    u8 min_ttl;

    unsigned int do_max_ttl : 1;
    u8 max_ttl;

    unsigned int do_min_len : 1;
    u16 min_len;

    unsigned int do_max_len : 1;
    u16 max_len;

    unsigned int do_tos : 1;
    u8 tos;

#ifdef ENABLE_IPV6
    // IPv6 prefix lengths for src_ip6/dst_ip6.
    // 0 and 128 both mean an exact (/128) match, so filters written before these fields existed (zeroed) keep matching exactly.
    // 1-127 match the address as a CIDR prefix (masked compare).
    // Appended after tos so they occupy what was trailing padding: every older field keeps its offset and sizeof(filter_ip_t) is unchanged.
    u8 src_cidr6;
    u8 dst_cidr6;
#endif
} typedef filter_ip_t;

struct filter_tcp
{
    unsigned int enabled : 1;

    unsigned int do_sport_min : 1;
    u16 sport_min;

    unsigned int do_sport_max : 1;
    u16 sport_max;

    unsigned int do_dport_min : 1;
    u16 dport_min;

    unsigned int do_dport_max : 1;
    u16 dport_max;

    // TCP flags.
    unsigned int do_urg : 1;
    unsigned int urg : 1;

    unsigned int do_ack : 1;
    unsigned int ack : 1;

    unsigned int do_rst : 1;
    unsigned int rst : 1;

    unsigned int do_psh : 1;
    unsigned int psh : 1;

    unsigned int do_syn : 1;
    unsigned int syn : 1;

    unsigned int do_fin : 1;
    unsigned int fin : 1;

    unsigned int do_ece : 1;
    unsigned int ece : 1;

    unsigned int do_cwr : 1;
    unsigned int cwr : 1;
} typedef filter_tcp_t;

struct filter_udp
{
    unsigned int enabled : 1;

    unsigned int do_sport_min : 1;
    u16 sport_min;

    unsigned int do_sport_max : 1;
    u16 sport_max;

    unsigned int do_dport_min : 1;
    u16 dport_min;

    unsigned int do_dport_max : 1;
    u16 dport_max;
} typedef filter_udp_t;

struct filter_icmp
{
    unsigned int enabled : 1;

    unsigned int do_code : 1;
    u8 code;

    unsigned int do_type : 1;
    u8 type;
} typedef filter_icmp_t;

struct filter
{
    unsigned int set : 1;
    unsigned int log : 1;
    unsigned int enabled : 1;

    u8 action;
    u16 block_time;

#ifdef ENABLE_RL_IP
    unsigned int do_ip_pps : 1;
    u64 ip_pps;

    unsigned int do_ip_bps : 1;
    u64 ip_bps;
#endif

#ifdef ENABLE_RL_FLOW
    unsigned int do_flow_pps : 1;
    u64 flow_pps;

    unsigned int do_flow_bps : 1;
    u64 flow_bps;
#endif
    
    filter_ip_t ip;

    filter_tcp_t tcp;
    filter_udp_t udp;
    filter_icmp_t icmp;
} __attribute__((__aligned__(8))) typedef filter_t;

// Global packet counters (map_stats, per-CPU, single entry at key 0).
// The first three fields are the original layout; every later field was appended so readers of the old prefix keep working.
struct stats
{
    // Packets matched by an allow filter (action 1) or by the allowlist (map_allow/map_allow6).
    u64 allowed;

    // Packets dropped (malformed, block maps, range drop maps and drop filters).
    u64 dropped;

    // Packets passed without matching anything.
    u64 passed;

    // Byte counters for the three counters above (full frame length, data_end - data).
    u64 allowed_bytes;
    u64 dropped_bytes;
    u64 passed_bytes;

    // Subset of dropped: drops because the source was in map_block/map_block6/map_block_perm/map_block6_perm (requires DO_STATS_ON_BLOCK_MAP).
    u64 dropped_block;
    u64 dropped_block_bytes;

    // Subset of dropped: drops because the source was in map_range_drop/map_range_drop6 (requires DO_STATS_ON_IP_RANGE_DROP_MAP).
    u64 dropped_range;
    u64 dropped_range_bytes;

    // Subset of allowed: passes because the source was in map_allow/map_allow6.
    u64 allowlist_passed;
    u64 allowlist_passed_bytes;

    // Filter log events lost because bpf_ringbuf_reserve() on map_filter_log failed (ring buffer full).
    u64 filter_log_lost;
} typedef stats_t;

// Per-filter counters (map_filter_stats, per-CPU array indexed by filter slot).
// Incremented for every packet that matches the filter, whether or not the filter logs.
struct filter_stats
{
    u64 packets;
    u64 bytes;
} typedef filter_stats_t;

struct cl_stats
{
    u64 pps;
    u64 bps;
    u64 next_update;
} typedef cl_stats_t;

struct flow
{
    u32 ip;
    u16 port;
    u8 protocol;
} typedef flow_t;

struct flow6
{
    u128 ip;
    u16 port;
    u8 protocol;
} typedef flow6_t;

// Filter log event (map_filter_log ring buffer).
// For IPv4 packets src_ip/dst_ip are set and src_ip6/dst_ip6 are zero.
// For IPv6 packets src_ip6/dst_ip6 carry the full 16 address bytes (network byte order) and src_ip/dst_ip are zero.
struct filter_log_event
{
    u64 ts;
    int filter_id;

    int length;

    u32 src_ip;
    u32 src_ip6[4];

    u16 src_port;

    u32 dst_ip;
    u32 dst_ip6[4];

    u16 dst_port;

    u8 protocol;

    u64 ip_pps;
    u64 ip_bps;

    u64 flow_pps;
    u64 flow_bps;
} typedef filter_log_event_t;

// IPv4 LPM trie key (map_range_drop, map_allow).
// data is the network address in network byte order.
struct lpm_trie_key
{
    u32 prefix_len;
    u32 data;
} typedef lpm_trie_key_t;

// IPv6 LPM trie key (map_range_drop6, map_allow6).
// data is the 16 raw address bytes in network byte order; prefix_len is 0-128.
// u32[4] rather than u128 so there is no alignment padding between prefix_len and data (the kernel requires data at offset 4).
struct lpm_trie_key6
{
    u32 prefix_len;
    u32 data[4];
} typedef lpm_trie_key6_t;