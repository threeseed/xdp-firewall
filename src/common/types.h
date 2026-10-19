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

    // Shadow (dry-run) filter: a match is counted in map_filter_stats (shadow_packets/shadow_bytes) and evaluation continues with the next filter as if this one had not matched.
    // A shadow filter never drops, passes, blocks or logs. Rate limit state is per source/flow (not per filter), so it is updated the same way as for an enforced filter.
    // Sits in what was padding after enabled, so no older field moves.
    unsigned int shadow : 1;

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

    // The map_filter_stats index this filter counts into (0 to MAX_FILTER_STATS - 1).
    // Chosen by whoever writes the filter, so a filter keeps its counters when it moves to another slot or to the other buffer of map_filters.
    u32 stats_idx;
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

// Per-filter counters (map_filter_stats, per-CPU array indexed by filter_t's stats_idx).
// Incremented for every packet that matches the filter, whether or not the filter logs.
struct filter_stats
{
    // Matches of the filter while it was enforced (its action was taken).
    u64 packets;
    u64 bytes;

    // Matches of the filter while it was a shadow filter (nothing was done; evaluation continued).
    u64 shadow_packets;
    u64 shadow_bytes;
} typedef filter_stats_t;

// Built-in L3/L4 sanity checks (map_sanity, map_sanity_stats).
// Each reason has a mode (SANITY_MODE_*) in sanity_cfg_t and counters in map_sanity_stats at the reason's index.
#define SANITY_MODE_OFF 0
#define SANITY_MODE_SHADOW 1
#define SANITY_MODE_ENFORCE 2

// Source address is martian: IPv4 0/8, 127/8, 224/4 or 240/4 (incl. 255.255.255.255); IPv6 ::, ::1 or ff00::/8.
#define SANITY_MARTIAN_SRC 0

// Source address is one of the host's own addresses (map_local_addr/map_local_addr6).
#define SANITY_LAND 1

// TCP with no flags set (flags & 0x3F == 0).
#define SANITY_TCP_NULL 2

// TCP with SYN and FIN set.
#define SANITY_TCP_SYN_FIN 3

// TCP with FIN, PSH and URG set (Xmas scan).
#define SANITY_TCP_XMAS 4

// TCP data offset below 5 (header shorter than 20 bytes).
#define SANITY_TCP_BAD_DOFF 5

// TCP or UDP source or destination port 0.
#define SANITY_PORT_ZERO 6

// TCP SYN without ACK to a port not in the TCP port gate.
#define SANITY_PORT_GATE_TCP 7

// UDP to a port not in the UDP port gate (DHCP client port 68 excepted).
#define SANITY_PORT_GATE_UDP 8

// Room for reasons (sanity_cfg_t's mode array and map_sanity_stats' entries); reasons may be added below this without a layout change.
#define SANITY_REASONS 16

// Sanity check modes (map_sanity, array, single entry at key 0). A zeroed entry turns every check off.
struct sanity_cfg
{
    u8 mode[SANITY_REASONS];
} typedef sanity_cfg_t;

// Per-reason sanity counters (map_sanity_stats, per-CPU array indexed by SANITY_*).
struct sanity_stats
{
    // Packets the reason dropped (mode enforce).
    u64 dropped;
    u64 dropped_bytes;

    // Packets the reason would have dropped (mode shadow); they were passed on to the rest of the program.
    u64 would_drop;
    u64 would_drop_bytes;
} typedef sanity_stats_t;

// Port gate keys (map_port_gate).
#define PORT_GATE_TCP 0
#define PORT_GATE_UDP 1

// The DHCP client port, always let through by the UDP port gate (replies from a DHCP server).
#define PORT_GATE_DHCP_CLIENT 68

// A stateless port gate (map_port_gate, array with an entry per PORT_GATE_* key).
// Bit (port & 63) of bits[port >> 6] is set for every allowed destination port.
// enabled is 0 for an empty or unset gate, which lets everything through (the gate is off).
struct port_gate
{
    u32 enabled;
    u32 reserved;
    u64 bits[1024];
} typedef port_gate_t;

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