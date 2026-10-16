#pragma once

// Enables dynamic filters.
// Disable this for better performance if you only plan on adding entries to the block and drop maps.
#define ENABLE_FILTERS

// Enables IPv4 range drop map (map_range_drop) and, together with ENABLE_IPV6, the IPv6 range drop map (map_range_drop6).
// Disable this if you don't plan on adding IP ranges to the drop maps as it will increase performance.
//#define ENABLE_IP_RANGE_DROP

// The maximum IP ranges supported in the IP range drop map.
#define MAX_IP_RANGES 4096

// The maximum IPv6 ranges supported in the IPv6 range drop map (map_range_drop6).
// The IPv6 range drop map exists when both ENABLE_IP_RANGE_DROP and ENABLE_IPV6 are defined.
#define MAX_IP_RANGES6 4096

// Enables the allowlist maps (map_allow for IPv4 and map_allow6 for IPv6, LPM tries).
// A source address matching an allowlist entry is passed (XDP_PASS) before the block maps, range drop maps and filters are checked.
// Disable this if you don't plan on using the allowlist as it will increase performance.
// Note: deployments that manage the allowlist from another process (e.g. the harana matrix plugin) build with this enabled.
//#define ENABLE_ALLOWLIST

// The maximum entries in each allowlist map (map_allow and map_allow6).
#define MAX_ALLOW_RANGES 4096

// The maximum amount of filters allowed.
// Decrease this value if you receive errors related to the BPF program being too large.
#define MAX_FILTERS 1000

// Feel free to comment this out if you don't want the `blocked` entry on the stats map to be incremented every single time a packet is dropped from the source IP being on the blocked map.
// Commenting this line out should increase performance when blocking malicious traffic.
#define DO_STATS_ON_BLOCK_MAP

// Similar to DO_STATS_ON_BLOCK_MAP, but for IPv4 range drop map.
#define DO_STATS_ON_IP_RANGE_DROP_MAP

// When this is defined, a check will occur inside the IPv4 and IPv6 filters.
// For IPv6 packets, if no IPv6 source/destination IP addresses are set, but there is an IPv4 address, it will ignore the filter.
// The same goes for IPv4, if there is no IPv4 source/destination IP addresses set, if an IPv6 address is set, it will ignore the filter.
#define ALLOW_SINGLE_IP_V4_V6

// Enables filter logging through XDP.
// If performance is a concern, it is best to disable this feature by commenting out the below line with //.
#define ENABLE_FILTER_LOGGING

// Maximum interfaces the firewall can attach to.
#define MAX_INTERFACES 6

// NOTE - If you're receiving a high volume of spoofed packets, it is recommended you disable rate limiting below.
// This is because the PPS/BPS counters are updated for every packet and with a spoofed attack, the LRU map will recycle a lot of entries resulting in additional load on the CPU.
// Enable source IP rate limiting.
//#define ENABLE_RL_IP

// Enable source flow rate limiting.
#define ENABLE_RL_FLOW

// Maximum entries in source IP rate limit map.
#define MAX_RL_IP 100000

// Maximum entries in source flow rate limit map.
#define MAX_RL_FLOW 100000

// Maximum entries in block map.
#define MAX_BLOCK 100000

// Maximum entries in the permanent block maps (map_block_perm and map_block6_perm).
// These are plain (non-LRU) hash maps, so permanent bans are never evicted to make room for temporary ones.
#define MAX_BLOCK_PERM 100000

// Enables IPv6.
// If you're not using IPv6, this will speed up performance of the XDP program.
#define ENABLE_IPV6

// If enabled, uses a newer bpf_loop() function when choosing a source port for a new connection.
// This allows for a much higher source port range. However, it requires a more recent kernel.
#define USE_NEW_LOOP

// Whether to enable chaining multiple XDP programs with this tool (1 = enable. 0 = disable).
#define XDP_MULTIPROG_ENABLED 1

// The XDP program's run priority (used for running multiple XDP programs together).
#define XDP_MULTIPROG_PRIORITY 10

// The action that indicates it should go onto the next program (default XDP_PASS).
#define XDP_MULTIPROG_ACTION XDP_PASS