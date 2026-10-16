#include <loader/utils/stats.h>

struct timespec last_update_time = {0};

// Number of u64 counters in stats_t (every field is a u64).
#define STATS_FIELDS (sizeof(stats_t) / sizeof(u64))

static u64 last_vals[STATS_FIELDS] = {0};

/**
 * Formats a counter (and optional byte counter) for display.
 *
 * @param buf The output buffer.
 * @param len The output buffer size.
 * @param pkts The packet counter (or packets per second).
 * @param bytes The byte counter (or bytes per second).
 * @param show_bytes Whether to show the byte counter.
 * @param per_second Whether the values are rates.
 *
 * @return void
 */
static void fmt_counter(char* buf, size_t len, u64 pkts, u64 bytes, int show_bytes, int per_second)
{
    if (show_bytes)
    {
        snprintf(buf, len, "%llu%s (%llu %s)", (unsigned long long)pkts, per_second ? " PPS" : "", (unsigned long long)bytes, per_second ? "B/s" : "B");
    }
    else
    {
        snprintf(buf, len, "%llu%s", (unsigned long long)pkts, per_second ? " PPS" : "");
    }
}

/**
 * Calculates and displays packet counters/stats.
 *
 * @param map_stats The stats map BPF FD.
 * @param cpus The amount of CPUs the host has.
 * @param per_second Calculate packet counters per second (PPS).
 *
 * @return 0 on success or 1 on failure.
 */
int calc_stats(int map_stats, int cpus, int per_second)
{
    u32 key = 0;

    stats_t stats[MAX_CPUS];
    memset(stats, 0, sizeof(stats));

    if (bpf_map_lookup_elem(map_stats, &key, stats) != 0)
    {
        return EXIT_FAILURE;
    }

    if (cpus > MAX_CPUS)
    {
        cpus = MAX_CPUS;
    }

    // Sum every counter across CPUs. stats_t only holds u64 counters, so treat it as an array.
    u64 totals[STATS_FIELDS];
    memset(totals, 0, sizeof(totals));

    for (int i = 0; i < cpus; i++)
    {
        const u64* vals = (const u64*)&stats[i];

        for (size_t j = 0; j < STATS_FIELDS; j++)
        {
            totals[j] += vals[j];
        }
    }

    stats_t sum;
    memcpy(&sum, totals, sizeof(sum));

    stats_t out = sum;

    if (per_second)
    {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        double elapsed_time = (now.tv_sec - last_update_time.tv_sec) +
                              (now.tv_nsec - last_update_time.tv_nsec) / 1e9;

        u64 rates[STATS_FIELDS];
        memcpy(rates, totals, sizeof(rates));

        if (elapsed_time > 0)
        {
            for (size_t j = 0; j < STATS_FIELDS; j++)
            {
                rates[j] = (totals[j] - last_vals[j]) / elapsed_time;
            }
        }

        memcpy(last_vals, totals, sizeof(last_vals));
        memcpy(&out, rates, sizeof(out));

        last_update_time = now;
    }

    char allowed_str[64];
    char dropped_str[64];
    char passed_str[64];
    char block_str[64];
    char range_str[64];
    char allowlist_str[64];

    fmt_counter(allowed_str, sizeof(allowed_str), out.allowed, out.allowed_bytes, 1, per_second);
    fmt_counter(dropped_str, sizeof(dropped_str), out.dropped, out.dropped_bytes, 1, per_second);
    fmt_counter(passed_str, sizeof(passed_str), out.passed, out.passed_bytes, 1, per_second);
    fmt_counter(block_str, sizeof(block_str), out.dropped_block, out.dropped_block_bytes, 0, per_second);
    fmt_counter(range_str, sizeof(range_str), out.dropped_range, out.dropped_range_bytes, 0, per_second);
    fmt_counter(allowlist_str, sizeof(allowlist_str), out.allowlist_passed, out.allowlist_passed_bytes, 0, per_second);

    // Clear the line first since its length varies.
    printf("\r\033[K");
    printf("\033[1;32mAllowed:\033[0m %s  |  ", allowed_str);
    printf("\033[1;31mDropped:\033[0m %s  |  ", dropped_str);
    printf("\033[1;34mPassed:\033[0m %s  |  ", passed_str);
    printf("Block: %s  |  Range: %s  |  Allowlist: %s  |  ", block_str, range_str, allowlist_str);

    // Lost filter log events are always shown as a total.
    printf("Log Lost: %llu", (unsigned long long)sum.filter_log_lost);

    fflush(stdout);

    return EXIT_SUCCESS;
}
