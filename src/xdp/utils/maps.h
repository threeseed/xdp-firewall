#pragma once

#include <common/int_types.h>
#include <common/types.h>

#include <xdp/utils/helpers.h>

struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, stats_t);
} map_stats SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCK);
    __type(key, u32);
    __type(value, u64);
} map_block SEC(".maps");

// Permanent IPv4 bans. A plain hash (not LRU) so entries are never evicted.
// Same key/value semantics as map_block (value 0 = permanent, otherwise CLOCK_MONOTONIC expiry in ns).
struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCK_PERM);
    __type(key, u32);
    __type(value, u64);
} map_block_perm SEC(".maps");

#ifdef ENABLE_IPV6
struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCK);
    __type(key, u128);
    __type(value, u64);
} map_block6 SEC(".maps");

// Permanent IPv6 bans. A plain hash (not LRU) so entries are never evicted.
struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCK_PERM);
    __type(key, u128);
    __type(value, u64);
} map_block6_perm SEC(".maps");
#endif

#ifdef ENABLE_ALLOWLIST
// IPv4 allowlist. The value is not read by the XDP program.
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ALLOW_RANGES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, lpm_trie_key_t);
    __type(value, u64);
} map_allow SEC(".maps");

#ifdef ENABLE_IPV6
// IPv6 allowlist. The value is not read by the XDP program.
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ALLOW_RANGES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, lpm_trie_key6_t);
    __type(value, u64);
} map_allow6 SEC(".maps");
#endif
#endif

#ifdef ENABLE_IP_RANGE_DROP
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_IP_RANGES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, lpm_trie_key_t);
    __type(value, u64);
} map_range_drop SEC(".maps");

#ifdef ENABLE_IPV6
// IPv6 range drop map. The value is not read by the XDP program (the LPM lookup itself guarantees the match).
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_IP_RANGES6);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, lpm_trie_key6_t);
    __type(value, u64);
} map_range_drop6 SEC(".maps");
#endif
#endif

#ifdef ENABLE_FILTERS
#ifdef ENABLE_RL_IP
struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RL_IP);
    __type(key, u32);
    __type(value, cl_stats_t);
} map_ip_stats SEC(".maps");

#ifdef ENABLE_IPV6
struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RL_IP);
    __type(key, u128);
    __type(value, cl_stats_t);
} map_ip6_stats SEC(".maps");
#endif
#endif

#ifdef ENABLE_RL_FLOW
struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RL_FLOW);
    __type(key, flow_t);
    __type(value, cl_stats_t);
} map_flow_stats SEC(".maps");

#ifdef ENABLE_IPV6
struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RL_FLOW);
    __type(key, flow6_t);
    __type(value, cl_stats_t);
} map_flow6_stats SEC(".maps");
#endif
#endif

// Two buffers of MAX_FILTERS filters (see FILTER_BUFFERS): slot i of buffer b is key b * MAX_FILTERS + i.
// Only the buffer map_filter_active names is evaluated; within it, slots are walked from 0 up to the first one whose set bit is clear.
// A plain (shared) array: the filters are the same on every CPU, and one write per slot is all an update costs.
struct 
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, FILTER_BUFFERS * MAX_FILTERS);
    __type(key, u32);
    __type(value, filter_t);
} map_filters SEC(".maps");

// The active map_filters buffer (0 or 1; only the low bit is read), single entry at key 0.
// Read once per packet, so flipping it swaps the whole rule set at once.
struct 
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} map_filter_active SEC(".maps");

// Per-filter packet/byte counters, indexed by filter_t's stats_idx (not by slot), so they follow a filter across slots and buffers.
struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_FILTER_STATS);
    __type(key, u32);
    __type(value, filter_stats_t);
} map_filter_stats SEC(".maps");

#ifdef ENABLE_FILTER_LOGGING
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} map_filter_log SEC(".maps");
#endif
#endif

#ifdef ENABLE_SANITY
// Sanity check modes (sanity_cfg_t), single entry at key 0. Zeroed (every check off) until a writer sets it.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, sanity_cfg_t);
} map_sanity SEC(".maps");

// Per-reason sanity counters, indexed by SANITY_*.
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, SANITY_REASONS);
    __type(key, u32);
    __type(value, sanity_stats_t);
} map_sanity_stats SEC(".maps");

// The stateless port gate: the TCP (PORT_GATE_TCP) and UDP (PORT_GATE_UDP) destination ports to let through.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, port_gate_t);
} map_port_gate SEC(".maps");

// The host's own IPv4 addresses (network byte order), for the land check. The value is not read.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_LOCAL_ADDRS);
    __type(key, u32);
    __type(value, u8);
} map_local_addr SEC(".maps");

#ifdef ENABLE_IPV6
// The host's own IPv6 addresses (the 16 raw address bytes), for the land check. The value is not read.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_LOCAL_ADDRS);
    __type(key, u128);
    __type(value, u8);
} map_local_addr6 SEC(".maps");
#endif
#endif
