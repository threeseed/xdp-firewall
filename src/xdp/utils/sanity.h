#pragma once

#include <common/all.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <xdp/utils/helpers.h>
#include <xdp/utils/stats.h>

#include <xdp/utils/maps.h>

#ifdef ENABLE_SANITY
static __always_inline int sanity_hit(const sanity_cfg_t* cfg, u32 reason, u64 bytes);
static __always_inline int sanity_check_l3(const sanity_cfg_t* cfg, struct iphdr* iph, struct ipv6hdr* iph6, u64 bytes);
static __always_inline int sanity_check_l4(const sanity_cfg_t* cfg, struct tcphdr* tcph, struct udphdr* udph, u64 bytes);
#endif

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "sanity.c"
