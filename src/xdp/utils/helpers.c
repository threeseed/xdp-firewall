#include <xdp/utils/helpers.h>

/**
 * Checks if an IP is within a specific CIDR range.
 * 
 * @param src_ip The source/main IP to check against.
 * @param net_ip The network IP.
 * @param cidr The CIDR range.
 * 
 * @return 1 on yes, 0 on no.
 */
static __always_inline int is_ip_in_range(u32 src_ip, u32 net_ip, u8 cidr)
{
    return !((src_ip ^ net_ip) & htonl(0xFFFFFFFFu << (32 - cidr)));
}

/**
 * Checks whether a key is in a block map and its block has not expired.
 * An expired entry is deleted from the map.
 * 
 * @param map The block map (map_block, map_block_perm, map_block6 or map_block6_perm).
 * @param key The source address key.
 * @param now The current time (bpf_ktime_get_ns(), CLOCK_MONOTONIC ns).
 * 
 * @return 1 if blocked, 0 otherwise.
 */
static __always_inline int check_block(void *map, const void *key, u64 now)
{
    u64 *expires = bpf_map_lookup_elem(map, key);

    if (!expires)
    {
        return 0;
    }

    // 0 = permanent.
    if (*expires > 0 && now > *expires)
    {
        bpf_map_delete_elem(map, key);

        return 0;
    }

    return 1;
}

#ifdef ENABLE_IPV6
/**
 * Checks if an IPv6 address (four words) is set (non-zero).
 * 
 * @param ip The IPv6 address.
 * 
 * @return 1 on yes, 0 on no.
 */
static __always_inline int is_ip6_set(const u32 *ip)
{
    return (ip[0] | ip[1] | ip[2] | ip[3]) != 0;
}

/**
 * Builds the network byte order mask of one 32-bit word of an IPv6 prefix.
 * 
 * @param cidr The prefix length (1-128).
 * @param word The word index (0-3).
 * 
 * @return The mask for that word.
 */
static __always_inline u32 ip6_word_mask(u8 cidr, int word)
{
    int bits = (int)cidr - (word * 32);

    if (bits <= 0)
    {
        return 0;
    }

    if (bits >= 32)
    {
        return 0xFFFFFFFFu;
    }

    return htonl(0xFFFFFFFFu << (32 - bits));
}

/**
 * Checks if an IPv6 address is within a network.
 * 
 * @param src_ip The address to check (network byte order words).
 * @param net_ip The network address (network byte order words).
 * @param cidr The prefix length. 0 and 128 both mean an exact match.
 * 
 * @return 1 on yes, 0 on no.
 */
static __always_inline int is_ip6_in_range(const u32 *src_ip, const u32 *net_ip, u8 cidr)
{
    if (cidr == 0 || cidr >= 128)
    {
        return src_ip[0] == net_ip[0] && src_ip[1] == net_ip[1] && src_ip[2] == net_ip[2] && src_ip[3] == net_ip[3];
    }

    return !(((src_ip[0] ^ net_ip[0]) & ip6_word_mask(cidr, 0)) |
             ((src_ip[1] ^ net_ip[1]) & ip6_word_mask(cidr, 1)) |
             ((src_ip[2] ^ net_ip[2]) & ip6_word_mask(cidr, 2)) |
             ((src_ip[3] ^ net_ip[3]) & ip6_word_mask(cidr, 3)));
}
#endif

#ifdef ENABLE_IP_RANGE_DROP
/**
 * Checks if the IP is in the IP range drop map.
 * 
 * @param ip The IP address.
 * 
 * @return 1 on yes or 0 on no.
 */
static __always_inline int check_ip_range_drop(u32 ip)
{
    lpm_trie_key_t key = {0};
    key.prefix_len = 32;
    key.data = ip;

    u64 *lookup = bpf_map_lookup_elem(&map_range_drop, &key);

    if (lookup)
    {
        u32 bit_mask = *lookup >> 32;
        u32 prefix = *lookup & 0xFFFFFFFF;

        // Check if matched.
        if ((ip & bit_mask) == prefix)
        {
            return 1;
        }
    }

    return 0;
}
#endif

#if defined(ENABLE_IP_RANGE_DROP) && defined(ENABLE_IPV6)
/**
 * Checks if the IPv6 address is in the IPv6 range drop map.
 * 
 * @param ip The IPv6 address (network byte order words).
 * 
 * @return 1 on yes or 0 on no.
 */
static __always_inline int check_ip6_range_drop(const u32 *ip)
{
    lpm_trie_key6_t key = {0};
    key.prefix_len = 128;
    memcpy(key.data, ip, sizeof(key.data));

    return bpf_map_lookup_elem(&map_range_drop6, &key) != NULL;
}
#endif

#ifdef ENABLE_ALLOWLIST
/**
 * Checks if the IP is in the IPv4 allowlist.
 * 
 * @param ip The IP address (network byte order).
 * 
 * @return 1 on yes or 0 on no.
 */
static __always_inline int check_allow(u32 ip)
{
    lpm_trie_key_t key = {0};
    key.prefix_len = 32;
    key.data = ip;

    return bpf_map_lookup_elem(&map_allow, &key) != NULL;
}

#ifdef ENABLE_IPV6
/**
 * Checks if the IPv6 address is in the IPv6 allowlist.
 * 
 * @param ip The IPv6 address (network byte order words).
 * 
 * @return 1 on yes or 0 on no.
 */
static __always_inline int check_allow6(const u32 *ip)
{
    lpm_trie_key6_t key = {0};
    key.prefix_len = 128;
    memcpy(key.data, ip, sizeof(key.data));

    return bpf_map_lookup_elem(&map_allow6, &key) != NULL;
}
#endif
#endif