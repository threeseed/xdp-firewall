#include <loader/utils/helpers.h>

/**
 * Prints help menu.
 * 
 * @return void
 */
void print_help_menu()
{
    printf("Usage: xdpfw [OPTIONS]\n\n");

    printf("  -c, --config         Config file location (default: /etc/xdpfw/xdpfw.conf).\n");
    printf("  -o, --offload        Load the XDP program in hardware/offload mode.\n");
    printf("  -s, --skb            Force the XDP program to load with SKB mode instead of DRV.\n");
    printf("  -t, --time           Duration to run the program (seconds). 0 or unset = infinite.\n");
    printf("  -l, --list           Print config details including filters (exits after execution).\n");
    printf("  -h, --help           Show this help message.\n\n");
    printf("  -v, --verbose        Override config's verbose value.\n");
    printf("      --log-file       Override config's log file value.\n");
    printf("  -i, --interface      Override config's interface value.\n");
    printf("  -u, --update-time    Override config's update time value.\n");
    printf("  -n, --no-stats       Override config's no stats value.\n");
    printf("      --stats-ps       Override config's stats per second value.\n");
    printf("      --stdout-ut      Override config's stdout update time value.\n");
    printf("      --filter-log-consume  Override config's filter log consume value (0 = leave map_filter_log to another consumer).\n");
}

/**
 * Handles signals from user.
 * 
 * @param code Signal code.
 * 
 * @return void
 */
void hdl_signal(int code)
{
    cont = 0;
}

/**
 * Parses an IP string with CIDR support. Stores IP in network byte order in ip.ip and CIDR in ip.cidr.
 * 
 * @param ip The IP string.
 * 
 * @return Returns an IP structure with IP and CIDR. 
 */
ip_range_t parse_ip_range(const char *ip)
{
    ip_range_t ret = {0};
    ret.cidr = 32;

    char ip_copy[INET_ADDRSTRLEN + 3];
    strncpy(ip_copy, ip, sizeof(ip_copy) - 1);
    ip_copy[sizeof(ip_copy) - 1] = '\0';

    char *token = strtok(ip_copy, "/");

    if (token)
    {
        ret.ip = inet_addr(token);

        token = strtok(NULL, "/");

        if (token)
        {
            ret.cidr = (u8) strtoul(token, NULL, 10);
        }
    }

    return ret;
}

/**
 * Converts an IPv4 prefix length to a netmask in network byte order.
 * 
 * @param cidr The prefix length (0-32).
 * 
 * @return The netmask in network byte order.
 */
u32 cidr_to_mask(u8 cidr)
{
    if (cidr == 0)
    {
        return 0;
    }

    if (cidr >= 32)
    {
        return 0xFFFFFFFFu;
    }

    return htonl(0xFFFFFFFFu << (32 - cidr));
}

/**
 * Checks whether an address string looks like an IPv6 address (contains ':').
 * 
 * @param ip The address string.
 * 
 * @return 1 on yes, 0 on no.
 */
int is_ip6_str(const char* ip)
{
    return ip && strchr(ip, ':') != NULL;
}

/**
 * Clears the host bits of an IPv6 address.
 * 
 * @param ip The address (four words, network byte order).
 * @param cidr The prefix length (0-128).
 * 
 * @return void
 */
void mask_ip6(u32* ip, u8 cidr)
{
    for (int i = 0; i < 4; i++)
    {
        int bits = (int)cidr - (i * 32);

        if (bits >= 32)
        {
            continue;
        }

        if (bits <= 0)
        {
            ip[i] = 0;

            continue;
        }

        ip[i] &= htonl(0xFFFFFFFFu << (32 - bits));
    }
}

/**
 * Parses an IPv6 address string with optional prefix length ("addr" or "addr/len").
 * 
 * @param ip The address string.
 * 
 * @return The parsed address and prefix length. success is 0 if the address or prefix length is invalid.
 */
ip6_range_t parse_ip6_range(const char* ip)
{
    ip6_range_t ret = {0};
    ret.cidr = 128;

    if (!ip)
    {
        return ret;
    }

    char ip_copy[INET6_ADDRSTRLEN + 5];
    strncpy(ip_copy, ip, sizeof(ip_copy) - 1);
    ip_copy[sizeof(ip_copy) - 1] = '\0';

    char* slash = strchr(ip_copy, '/');

    if (slash)
    {
        *slash = '\0';

        char* end = NULL;
        unsigned long len = strtoul(slash + 1, &end, 10);

        if (end == slash + 1 || *end != '\0' || len > 128)
        {
            return ret;
        }

        ret.cidr = (u8)len;
    }

    struct in6_addr addr;

    if (inet_pton(AF_INET6, ip_copy, &addr) != 1)
    {
        return ret;
    }

    memcpy(ret.ip, &addr, sizeof(ret.ip));

    ret.success = 1;

    return ret;
}

/**
 * Retrieves protocol name by ID.
 * 
 * @param id The protocol ID
 * 
 * @return The protocol string. 
 */
const char* get_protocol_str_by_id(int id)
{
    switch (id)
    {
        case IPPROTO_TCP:
            return "TCP";

        case IPPROTO_UDP:
            return "UDP";
        
        case IPPROTO_ICMP:
            return "ICMP";

        case IPPROTO_ICMPV6:
            return "ICMPv6";
    }

    return "N/A";
}

/**
 * Prints tool name and author.
 * 
 * @return void
 */
void print_tool_info()
{
    printf(
        " __  ______  ____    _____ _                        _ _ \n"
        " \\ \\/ /  _ \\|  _ \\  |  ___(_)_ __ _____      ____ _| | |\n"
        "  \\  /| | | | |_) | | |_  | | '__/ _ \\ \\ /\\ / / _` | | |\n"
        "  /  \\| |_| |  __/  |  _| | | | |  __/\\ V  V / (_| | | |\n"
        " /_/\\_\\____/|_|     |_|   |_|_|  \\___| \\_/\\_/ \\__,_|_|_|\n"
        "\n\n"
    );
}

/**
 * Retrieves the current CLOCK_MONOTONIC time in nanoseconds.
 * 
 * This is the clock bpf_ktime_get_ns() reads in the XDP program, so block expiry times computed from it compare correctly there.
 * (The previous implementation used sysinfo().uptime, which has one second resolution and is CLOCK_BOOTTIME based.)
 * 
 * @return The current CLOCK_MONOTONIC time in nanoseconds.
 */
u64 get_boot_nano_time()
{
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ((u64)ts.tv_sec * 1000000000ULL) + (u64)ts.tv_nsec;
}

/**
 * Parses a port range string and returns the minimum and maximum port.
 * 
 * @param range_str The port range string.
 * 
 * @return The port range as port_range_t type. Fields will be set to 0 on failure.
 */
port_range_t parse_port_range(const char* range_str)
{
    port_range_t ret = {0};

    if (!range_str)
    {
        return ret;
    }

    // Copy range string.
    char range_str_copy[24];
    strncpy(range_str_copy, range_str, sizeof(range_str_copy) - 1);
    range_str_copy[sizeof(range_str_copy) - 1] = '\0';

    // First scan for port ranges with ":".
    char* start = range_str_copy;
    char* end = strchr(range_str_copy, '-');

    if (!end)
    {
        end = strchr(range_str_copy, ':');
    }

    if (end)
    {
        *end = '\0';
        end++;
    }

    char *end_ptr = NULL;

    ret.min = strtol(start, &end_ptr, 10);

    if (end_ptr == start || (*end_ptr != '\0' && !isspace((unsigned char)*end_ptr)))
    {
        return ret;
    }

    if (end)
    {
        ret.max = strtol(end, &end_ptr, 10);

        if (end_ptr == end || (*end_ptr != '\0' && !isspace((unsigned char)*end_ptr)))
        {
            return ret;
        }
    }
    else
    {
        ret.max = ret.min;
    }

    ret.success = 1;

    return ret;
}