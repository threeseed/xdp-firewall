#include <xdp/utils/sanity.h>

#ifdef ENABLE_SANITY
/**
 * Records a sanity check hit and says whether to drop the packet.
 * In enforce mode the hit counts as dropped; in shadow mode it counts as would_drop and the packet goes on.
 *
 * @param cfg A pointer to the sanity config (map_sanity), or NULL.
 * @param reason The reason (SANITY_*).
 * @param bytes The packet length in bytes.
 *
 * @return 1 to drop the packet (enforce) or 0 to go on (off or shadow).
 */
static __always_inline int sanity_hit(const sanity_cfg_t* cfg, u32 reason, u64 bytes)
{
    if (!cfg || reason >= SANITY_REASONS)
    {
        return 0;
    }

    u8 mode = cfg->mode[reason];

    if (mode == SANITY_MODE_OFF)
    {
        return 0;
    }

    sanity_stats_t* stats = bpf_map_lookup_elem(&map_sanity_stats, &reason);

    if (mode == SANITY_MODE_ENFORCE)
    {
        if (stats)
        {
            stats->dropped++;
            stats->dropped_bytes += bytes;
        }

        return 1;
    }

    if (stats)
    {
        stats->would_drop++;
        stats->would_drop_bytes += bytes;
    }

    return 0;
}

/**
 * Checks whether a reason is on (shadow or enforce), so its test can be skipped otherwise.
 *
 * @param cfg A pointer to the sanity config, or NULL.
 * @param reason The reason (SANITY_*).
 *
 * @return 1 on yes, 0 on no.
 */
static __always_inline int sanity_on(const sanity_cfg_t* cfg, u32 reason)
{
    return cfg && reason < SANITY_REASONS && cfg->mode[reason] != SANITY_MODE_OFF;
}

/**
 * Runs the layer-3 sanity checks (martian and land source addresses).
 *
 * @param cfg A pointer to the sanity config (map_sanity), or NULL (every check off).
 * @param iph The IPv4 header, or NULL.
 * @param iph6 The IPv6 header, or NULL.
 * @param bytes The packet length in bytes.
 *
 * @return 1 to drop the packet or 0 to go on.
 */
static __always_inline int sanity_check_l3(const sanity_cfg_t* cfg, struct iphdr* iph, struct ipv6hdr* iph6, u64 bytes)
{
    if (!cfg)
    {
        return 0;
    }

    if (iph)
    {
        if (sanity_on(cfg, SANITY_MARTIAN_SRC))
        {
            // 0/8, 127/8, 224/4 (multicast) and 240/4 (reserved, incl. 255.255.255.255).
            u8 first = ntohl(iph->saddr) >> 24;

            if ((first == 0 || first == 127 || first >= 224) && sanity_hit(cfg, SANITY_MARTIAN_SRC, bytes))
            {
                return 1;
            }
        }

        if (sanity_on(cfg, SANITY_LAND))
        {
            u32 saddr = iph->saddr;

            if (bpf_map_lookup_elem(&map_local_addr, &saddr) && sanity_hit(cfg, SANITY_LAND, bytes))
            {
                return 1;
            }
        }
    }
#ifdef ENABLE_IPV6
    else if (iph6)
    {
        const u32* src = iph6->saddr.in6_u.u6_addr32;

        if (sanity_on(cfg, SANITY_MARTIAN_SRC))
        {
            // :: (unspecified), ::1 (loopback) and ff00::/8 (multicast).
            int unspecified = (src[0] | src[1] | src[2] | src[3]) == 0;
            int loopback = (src[0] | src[1] | src[2]) == 0 && src[3] == htonl(1);
            int multicast = iph6->saddr.in6_u.u6_addr8[0] == 0xff;

            if ((unspecified || loopback || multicast) && sanity_hit(cfg, SANITY_MARTIAN_SRC, bytes))
            {
                return 1;
            }
        }

        if (sanity_on(cfg, SANITY_LAND))
        {
            u128 saddr = 0;
            memcpy(&saddr, src, sizeof(saddr));

            if (bpf_map_lookup_elem(&map_local_addr6, &saddr) && sanity_hit(cfg, SANITY_LAND, bytes))
            {
                return 1;
            }
        }
    }
#endif

    return 0;
}

/**
 * Checks whether a port gate lets a destination port through.
 *
 * @param key The gate (PORT_GATE_TCP or PORT_GATE_UDP).
 * @param port The destination port (host byte order).
 *
 * @return 1 when the gate is on and the port is not in it, 0 otherwise.
 */
static __always_inline int port_gate_closed(u32 key, u16 port)
{
    port_gate_t* gate = bpf_map_lookup_elem(&map_port_gate, &key);

    if (!gate || !gate->enabled)
    {
        return 0;
    }

    return !(gate->bits[(port >> 6) & 1023] & (1ULL << (port & 63)));
}

/**
 * Runs the layer-4 sanity checks (TCP flags and data offset, port 0) and the port gate.
 * Masks the TCP flags with 0x3F, so ECE and CWR neither hide a scan nor cause a false positive.
 *
 * @param cfg A pointer to the sanity config (map_sanity), or NULL (every check off).
 * @param tcph The TCP header, or NULL.
 * @param udph The UDP header, or NULL.
 * @param bytes The packet length in bytes.
 *
 * @return 1 to drop the packet or 0 to go on.
 */
static __always_inline int sanity_check_l4(const sanity_cfg_t* cfg, struct tcphdr* tcph, struct udphdr* udph, u64 bytes)
{
    if (!cfg)
    {
        return 0;
    }

    if (tcph)
    {
        if (sanity_on(cfg, SANITY_PORT_ZERO) && (tcph->source == 0 || tcph->dest == 0) && sanity_hit(cfg, SANITY_PORT_ZERO, bytes))
        {
            return 1;
        }

        // FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10, URG 0x20 (byte 13 of the header).
        u8 flags = ((u8*)tcph)[13] & 0x3F;

        if (flags == 0 && sanity_hit(cfg, SANITY_TCP_NULL, bytes))
        {
            return 1;
        }

        if ((flags & 0x03) == 0x03 && sanity_hit(cfg, SANITY_TCP_SYN_FIN, bytes))
        {
            return 1;
        }

        if ((flags & 0x29) == 0x29 && sanity_hit(cfg, SANITY_TCP_XMAS, bytes))
        {
            return 1;
        }

        if (tcph->doff < 5 && sanity_hit(cfg, SANITY_TCP_BAD_DOFF, bytes))
        {
            return 1;
        }

        // A connection attempt (SYN without ACK) to a port nothing listens on.
        if (sanity_on(cfg, SANITY_PORT_GATE_TCP) && (flags & 0x12) == 0x02 && port_gate_closed(PORT_GATE_TCP, ntohs(tcph->dest)) && sanity_hit(cfg, SANITY_PORT_GATE_TCP, bytes))
        {
            return 1;
        }
    }
    else if (udph)
    {
        if (sanity_on(cfg, SANITY_PORT_ZERO) && (udph->source == 0 || udph->dest == 0) && sanity_hit(cfg, SANITY_PORT_ZERO, bytes))
        {
            return 1;
        }

        u16 dport = ntohs(udph->dest);

        if (sanity_on(cfg, SANITY_PORT_GATE_UDP) && dport != PORT_GATE_DHCP_CLIENT && port_gate_closed(PORT_GATE_UDP, dport) && sanity_hit(cfg, SANITY_PORT_GATE_UDP, bytes))
        {
            return 1;
        }
    }

    return 0;
}
#endif
