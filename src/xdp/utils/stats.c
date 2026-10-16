#include <xdp/utils/stats.h>

/**
 * Increments the packet and byte counters of the stats map.
 * 
 * @param stats A pointer to the (per-CPU) stats map value.
 * @param type The stats type.
 * @param bytes The packet length in bytes.
 * 
 * @return 0 on success or 1 if stats is NULL.
 */
static __always_inline int inc_pkt_stats(stats_t* stats, STATS_TYPE_T type, u64 bytes)
{
    if (!stats)
    {
        return 1;
    }

    switch (type)
    {
        case STATS_TYPE_ALLOWED:
            stats->allowed++;
            stats->allowed_bytes += bytes;

            break;

        case STATS_TYPE_PASSED:
            stats->passed++;
            stats->passed_bytes += bytes;

            break;

        case STATS_TYPE_DROPPED:
            stats->dropped++;
            stats->dropped_bytes += bytes;

            break;

        case STATS_TYPE_DROPPED_BLOCK:
            stats->dropped++;
            stats->dropped_bytes += bytes;

            stats->dropped_block++;
            stats->dropped_block_bytes += bytes;

            break;

        case STATS_TYPE_DROPPED_RANGE:
            stats->dropped++;
            stats->dropped_bytes += bytes;

            stats->dropped_range++;
            stats->dropped_range_bytes += bytes;

            break;

        case STATS_TYPE_ALLOWED_ALLOWLIST:
            stats->allowed++;
            stats->allowed_bytes += bytes;

            stats->allowlist_passed++;
            stats->allowlist_passed_bytes += bytes;

            break;
    }

    return 0;
}