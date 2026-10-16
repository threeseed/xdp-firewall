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

struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_FILTERS);
    __type(key, u32);
    __type(value, filter_t);
} map_filters SEC(".maps");

// Per-filter packet/byte counters, indexed by the same slot as map_filters.
struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_FILTERS);
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