// Verdict tests for the XDP program, run through BPF_PROG_TEST_RUN (needs root or CAP_BPF + CAP_NET_ADMIN, nothing is attached).
// Usage: xdpfw-test [path to xdp_prog.o built with the deployment defines]
// Covers shadow filters, the map_filters buffer flip, every sanity reason (enforce and shadow), the port gate and the allowlist bypass.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <common/all.h>

#ifndef XDP_DROP
#define XDP_DROP 1
#define XDP_PASS 2
#endif

static int failures = 0;
static int checks = 0;

static int prog_fd;
static int map_filters, map_filter_active, map_filter_stats, map_sanity, map_sanity_stats, map_port_gate, map_local_addr, map_allow;

#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int ncpus;

/**
 * A test packet.
 */
struct pkt
{
    unsigned char data[256];
    int len;
};

static void eth(struct pkt* p, int ipv6)
{
    struct ethhdr* e = (struct ethhdr*)p->data;
    memset(e, 0, sizeof(*e));
    e->h_proto = htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP);
}

/**
 * Builds an IPv4 TCP packet.
 */
static struct pkt tcp4(const char* src, const char* dst, u16 sport, u16 dport, u8 flags, u8 doff)
{
    struct pkt p = {0};
    eth(&p, 0);

    struct iphdr* ip = (struct iphdr*)(p.data + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, src, &ip->saddr);
    inet_pton(AF_INET, dst, &ip->daddr);

    struct tcphdr* tcp = (struct tcphdr*)(ip + 1);
    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    tcp->doff = doff;
    ((u8*)tcp)[13] = flags;

    p.len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->tot_len = htons(p.len - sizeof(struct ethhdr));

    return p;
}

/**
 * Builds an IPv4 UDP packet.
 */
static struct pkt udp4(const char* src, const char* dst, u16 sport, u16 dport)
{
    struct pkt p = {0};
    eth(&p, 0);

    struct iphdr* ip = (struct iphdr*)(p.data + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    inet_pton(AF_INET, src, &ip->saddr);
    inet_pton(AF_INET, dst, &ip->daddr);

    struct udphdr* udp = (struct udphdr*)(ip + 1);
    udp->source = htons(sport);
    udp->dest = htons(dport);
    udp->len = htons(sizeof(struct udphdr));

    p.len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    ip->tot_len = htons(p.len - sizeof(struct ethhdr));

    return p;
}

/**
 * Builds an IPv6 UDP packet.
 */
static struct pkt udp6(const char* src, const char* dst, u16 sport, u16 dport)
{
    struct pkt p = {0};
    eth(&p, 1);

    struct ipv6hdr* ip = (struct ipv6hdr*)(p.data + sizeof(struct ethhdr));
    ip->version = 6;
    ip->hop_limit = 64;
    ip->nexthdr = IPPROTO_UDP;
    inet_pton(AF_INET6, src, &ip->saddr);
    inet_pton(AF_INET6, dst, &ip->daddr);

    struct udphdr* udp = (struct udphdr*)(ip + 1);
    udp->source = htons(sport);
    udp->dest = htons(dport);
    udp->len = htons(sizeof(struct udphdr));
    ip->payload_len = udp->len;

    p.len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);

    return p;
}

/**
 * Runs the program once on a packet.
 *
 * @return The XDP verdict.
 */
static int run(struct pkt p)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = p.data, .data_size_in = p.len, .repeat = 1);

    int ret = bpf_prog_test_run_opts(prog_fd, &opts);

    if (ret != 0)
    {
        printf("bpf_prog_test_run_opts failed (%d)\n", ret);
        exit(2);
    }

    return opts.retval;
}

static void set_active(u32 active)
{
    u32 key = 0;
    bpf_map_update_elem(map_filter_active, &key, &active, BPF_ANY);
}

static void put_filter(u32 key, filter_t* f)
{
    bpf_map_update_elem(map_filters, &key, f, BPF_ANY);
}

static void clear_filters(void)
{
    filter_t empty = {0};

    for (u32 i = 0; i < FILTER_BUFFERS * MAX_FILTERS; i++)
    {
        put_filter(i, &empty);
    }

    set_active(0);
}

/**
 * Sums a map_filter_stats entry over every CPU.
 */
static filter_stats_t filter_stats(u32 idx)
{
    filter_stats_t per_cpu[ncpus];
    filter_stats_t sum = {0};

    memset(per_cpu, 0, sizeof(per_cpu));
    bpf_map_lookup_elem(map_filter_stats, &idx, per_cpu);

    for (int i = 0; i < ncpus; i++)
    {
        sum.packets += per_cpu[i].packets;
        sum.bytes += per_cpu[i].bytes;
        sum.shadow_packets += per_cpu[i].shadow_packets;
        sum.shadow_bytes += per_cpu[i].shadow_bytes;
    }

    return sum;
}

static void reset_filter_stats(u32 idx)
{
    filter_stats_t per_cpu[ncpus];

    memset(per_cpu, 0, sizeof(per_cpu));
    bpf_map_update_elem(map_filter_stats, &idx, per_cpu, BPF_ANY);
}

/**
 * Sums a map_sanity_stats entry over every CPU.
 */
static sanity_stats_t sanity_stats(u32 reason)
{
    sanity_stats_t per_cpu[ncpus];
    sanity_stats_t sum = {0};

    memset(per_cpu, 0, sizeof(per_cpu));
    bpf_map_lookup_elem(map_sanity_stats, &reason, per_cpu);

    for (int i = 0; i < ncpus; i++)
    {
        sum.dropped += per_cpu[i].dropped;
        sum.would_drop += per_cpu[i].would_drop;
    }

    return sum;
}

static void reset_sanity_stats(void)
{
    sanity_stats_t per_cpu[ncpus];

    memset(per_cpu, 0, sizeof(per_cpu));

    for (u32 i = 0; i < SANITY_REASONS; i++)
    {
        bpf_map_update_elem(map_sanity_stats, &i, per_cpu, BPF_ANY);
    }
}

static void set_sanity(u32 reason, u8 mode)
{
    sanity_cfg_t cfg = {0};
    u32 key = 0;

    if (reason < SANITY_REASONS)
    {
        cfg.mode[reason] = mode;
    }

    bpf_map_update_elem(map_sanity, &key, &cfg, BPF_ANY);
}

static void set_gate(u32 key, const u16* ports, int n)
{
    port_gate_t gate = {0};

    for (int i = 0; i < n; i++)
    {
        gate.bits[ports[i] >> 6] |= 1ULL << (ports[i] & 63);
    }

    gate.enabled = n > 0;

    bpf_map_update_elem(map_port_gate, &key, &gate, BPF_ANY);
}

/**
 * A drop filter on TCP destination port `dport`.
 */
static filter_t tcp_dport_filter(u16 dport, int action, int shadow, u32 stats_idx)
{
    filter_t f = {0};
    f.set = 1;
    f.enabled = 1;
    f.shadow = shadow;
    f.action = action;
    f.stats_idx = stats_idx;
    f.tcp.enabled = 1;
    f.tcp.do_dport_min = 1;
    f.tcp.dport_min = dport;
    f.tcp.do_dport_max = 1;
    f.tcp.dport_max = dport;

    return f;
}

static void test_filters(void)
{
    clear_filters();
    struct pkt syn80 = tcp4("198.51.100.7", "192.0.2.1", 40000, 80, 0x02, 5);

    CHECK(run(syn80) == XDP_PASS, "no filters passes");

    // A shadow drop filter counts and passes.
    reset_filter_stats(7);
    filter_t shadow = tcp_dport_filter(80, 0, 1, 7);
    put_filter(0, &shadow);

    CHECK(run(syn80) == XDP_PASS, "a matching shadow drop filter passes");
    filter_stats_t st = filter_stats(7);
    CHECK(st.shadow_packets == 1 && st.packets == 0, "shadow match counted as shadow (shadow %llu, enforced %llu)", (unsigned long long)st.shadow_packets, (unsigned long long)st.packets);
    CHECK(st.shadow_bytes == (u64)syn80.len, "shadow bytes counted (%llu)", (unsigned long long)st.shadow_bytes);

    // Evaluation goes on past a shadow filter: a later enforced drop filter drops.
    reset_filter_stats(8);
    filter_t enforce = tcp_dport_filter(80, 0, 0, 8);
    put_filter(1, &enforce);

    CHECK(run(syn80) == XDP_DROP, "an enforced filter after a shadow one drops");
    CHECK(filter_stats(7).shadow_packets == 2, "the shadow filter counted again");
    CHECK(filter_stats(8).packets == 1, "the enforced filter counted");

    // A shadow allow filter does not stop a later drop either.
    filter_t shadow_allow = tcp_dport_filter(80, 1, 1, 7);
    put_filter(0, &shadow_allow);
    CHECK(run(syn80) == XDP_DROP, "a shadow allow filter does not stop a later drop filter");

    // Promotion (same stats index, shadow cleared): the counters carry on in the enforced fields.
    reset_filter_stats(7);
    filter_t promoted = tcp_dport_filter(80, 0, 0, 7);
    put_filter(0, &promoted);
    CHECK(run(syn80) == XDP_DROP, "a promoted filter drops");
    st = filter_stats(7);
    CHECK(st.packets == 1 && st.shadow_packets == 0, "a promoted filter counts as enforced");

    // Non-matching port: passes, no count.
    struct pkt syn81 = tcp4("198.51.100.7", "192.0.2.1", 40000, 81, 0x02, 5);
    CHECK(run(syn81) == XDP_PASS, "a non-matching packet passes");
}

static void test_flip(void)
{
    clear_filters();
    struct pkt syn80 = tcp4("198.51.100.7", "192.0.2.1", 40000, 80, 0x02, 5);
    struct pkt syn443 = tcp4("198.51.100.7", "192.0.2.1", 40000, 443, 0x02, 5);

    // Buffer 0 (active) drops port 80.
    filter_t drop80 = tcp_dport_filter(80, 0, 0, 1);
    put_filter(0, &drop80);

    CHECK(run(syn80) == XDP_DROP && run(syn443) == XDP_PASS, "buffer 0 is evaluated while active");

    // Buffer 1 (inactive) drops port 443: not evaluated yet.
    filter_t drop443 = tcp_dport_filter(443, 0, 0, 2);
    put_filter(MAX_FILTERS, &drop443);

    CHECK(run(syn80) == XDP_DROP && run(syn443) == XDP_PASS, "the inactive buffer is not evaluated");

    // Flip.
    set_active(1);
    CHECK(run(syn80) == XDP_PASS && run(syn443) == XDP_DROP, "after the flip only buffer 1 is evaluated");

    // Clearing the old buffer changes nothing.
    filter_t empty = {0};
    put_filter(0, &empty);
    CHECK(run(syn80) == XDP_PASS && run(syn443) == XDP_DROP, "clearing the old buffer changes nothing");

    // Only the low bit of map_filter_active is read.
    set_active(2);
    CHECK(run(syn443) == XDP_PASS, "active 2 reads as buffer 0");

    // Counters follow stats_idx, not the slot: the same rule in buffer 1 slot 5 keeps counting into index 2.
    reset_filter_stats(2);
    put_filter(MAX_FILTERS, &empty);
    put_filter(MAX_FILTERS + 0, &drop80);
    drop443.stats_idx = 2;
    put_filter(MAX_FILTERS + 1, &drop443);
    set_active(1);
    CHECK(run(syn443) == XDP_DROP, "the rule moved to slot 1 still drops");
    CHECK(filter_stats(2).packets == 1, "its counters stayed at its stats index");

    clear_filters();
}

/**
 * Checks a sanity reason drops in enforce mode and passes (counting would_drop) in shadow mode.
 */
static void sanity_case(const char* what, u32 reason, struct pkt bad, struct pkt good)
{
    reset_sanity_stats();

    set_sanity(reason, SANITY_MODE_OFF);
    CHECK(run(bad) == XDP_PASS, "%s: off passes", what);

    set_sanity(reason, SANITY_MODE_ENFORCE);
    CHECK(run(bad) == XDP_DROP, "%s: enforce drops", what);
    CHECK(sanity_stats(reason).dropped == 1, "%s: enforce counted as dropped", what);
    CHECK(run(good) == XDP_PASS, "%s: enforce passes a good packet", what);

    set_sanity(reason, SANITY_MODE_SHADOW);
    CHECK(run(bad) == XDP_PASS, "%s: shadow passes", what);
    sanity_stats_t st = sanity_stats(reason);
    CHECK(st.would_drop == 1 && st.dropped == 1, "%s: shadow counted as would_drop (would_drop %llu, dropped %llu)", what, (unsigned long long)st.would_drop, (unsigned long long)st.dropped);

    set_sanity(SANITY_REASONS, SANITY_MODE_OFF);
}

static void test_sanity(void)
{
    clear_filters();

    struct pkt good = tcp4("198.51.100.7", "192.0.2.1", 40000, 443, 0x02, 5);

    sanity_case("martian 127/8", SANITY_MARTIAN_SRC, tcp4("127.0.0.1", "192.0.2.1", 40000, 443, 0x02, 5), good);
    sanity_case("martian 0/8", SANITY_MARTIAN_SRC, tcp4("0.1.2.3", "192.0.2.1", 40000, 443, 0x02, 5), good);
    sanity_case("martian 224/4", SANITY_MARTIAN_SRC, udp4("224.0.0.5", "192.0.2.1", 5000, 5000), good);
    sanity_case("martian 255.255.255.255", SANITY_MARTIAN_SRC, udp4("255.255.255.255", "192.0.2.1", 5000, 5000), good);
    sanity_case("martian ::1", SANITY_MARTIAN_SRC, udp6("::1", "2001:db8::1", 5000, 5000), udp6("2001:db8::7", "2001:db8::1", 5000, 5000));
    sanity_case("martian ::", SANITY_MARTIAN_SRC, udp6("::", "2001:db8::1", 5000, 5000), udp6("2001:db8::7", "2001:db8::1", 5000, 5000));
    sanity_case("martian ff02::1", SANITY_MARTIAN_SRC, udp6("ff02::1", "2001:db8::1", 5000, 5000), udp6("2001:db8::7", "2001:db8::1", 5000, 5000));

    u32 local = 0;
    u8 one = 1;
    inet_pton(AF_INET, "192.0.2.1", &local);
    bpf_map_update_elem(map_local_addr, &local, &one, BPF_ANY);
    sanity_case("land", SANITY_LAND, tcp4("192.0.2.1", "192.0.2.1", 40000, 443, 0x02, 5), good);
    bpf_map_delete_elem(map_local_addr, &local);

    sanity_case("tcp null", SANITY_TCP_NULL, tcp4("198.51.100.7", "192.0.2.1", 40000, 443, 0x00, 5), good);
    sanity_case("tcp null with ECE+CWR", SANITY_TCP_NULL, tcp4("198.51.100.7", "192.0.2.1", 40000, 443, 0xC0, 5), tcp4("198.51.100.7", "192.0.2.1", 40000, 443, 0xC2, 5));
    sanity_case("tcp syn+fin", SANITY_TCP_SYN_FIN, tcp4("198.51.100.7", "192.0.2.1", 40000, 443, 0x03, 5), good);
    sanity_case("tcp xmas", SANITY_TCP_XMAS, tcp4("198.51.100.7", "192.0.2.1", 40000, 443, 0x29, 5), good);
    sanity_case("tcp xmas with ECE+CWR", SANITY_TCP_XMAS, tcp4("198.51.100.7", "192.0.2.1", 40000, 443, 0xE9, 5), tcp4("198.51.100.7", "192.0.2.1", 40000, 443, 0xD2, 5));
    sanity_case("tcp doff 4", SANITY_TCP_BAD_DOFF, tcp4("198.51.100.7", "192.0.2.1", 40000, 443, 0x02, 4), good);
    sanity_case("tcp dst port 0", SANITY_PORT_ZERO, tcp4("198.51.100.7", "192.0.2.1", 40000, 0, 0x02, 5), good);
    sanity_case("udp src port 0", SANITY_PORT_ZERO, udp4("198.51.100.7", "192.0.2.1", 0, 3478), udp4("198.51.100.7", "192.0.2.1", 5000, 3478));

    // Port gate: TCP listens on 443 only, UDP on 3478 only.
    u16 tcp_ports[] = {443};
    u16 udp_ports[] = {3478};
    set_gate(PORT_GATE_TCP, tcp_ports, 1);
    set_gate(PORT_GATE_UDP, udp_ports, 1);

    sanity_case("tcp gate SYN to 22", SANITY_PORT_GATE_TCP, tcp4("198.51.100.7", "192.0.2.1", 40000, 22, 0x02, 5), good);

    set_sanity(SANITY_PORT_GATE_TCP, SANITY_MODE_ENFORCE);
    CHECK(run(tcp4("198.51.100.7", "192.0.2.1", 40000, 22, 0x12, 5)) == XDP_PASS, "tcp gate: SYN+ACK (a reply) to 22 passes");
    CHECK(run(tcp4("198.51.100.7", "192.0.2.1", 40000, 22, 0x10, 5)) == XDP_PASS, "tcp gate: ACK to 22 passes");
    CHECK(run(tcp4("198.51.100.7", "192.0.2.1", 40000, 443, 0xC2, 5)) == XDP_PASS, "tcp gate: SYN with ECE+CWR to 443 passes");
    CHECK(run(tcp4("198.51.100.7", "192.0.2.1", 40000, 444, 0xC2, 5)) == XDP_DROP, "tcp gate: SYN with ECE+CWR to 444 drops");

    // An empty gate is off.
    set_gate(PORT_GATE_TCP, NULL, 0);
    CHECK(run(tcp4("198.51.100.7", "192.0.2.1", 40000, 22, 0x02, 5)) == XDP_PASS, "tcp gate: an empty gate passes everything");
    set_gate(PORT_GATE_TCP, tcp_ports, 1);

    sanity_case("udp gate to 53", SANITY_PORT_GATE_UDP, udp4("198.51.100.7", "192.0.2.1", 5000, 53), udp4("198.51.100.7", "192.0.2.1", 5000, 3478));
    set_sanity(SANITY_PORT_GATE_UDP, SANITY_MODE_ENFORCE);
    CHECK(run(udp4("198.51.100.7", "192.0.2.1", 67, 68)) == XDP_PASS, "udp gate: DHCP client port 68 passes");
    CHECK(run(udp4("198.51.100.7", "192.0.2.1", 5000, 60000)) == XDP_DROP, "udp gate: no high-port exemption");
    CHECK(run(udp6("2001:db8::7", "2001:db8::1", 5000, 3478)) == XDP_PASS, "udp gate: IPv6 to an allowed port passes");
    CHECK(run(udp6("2001:db8::7", "2001:db8::1", 5000, 53)) == XDP_DROP, "udp gate: IPv6 to a closed port drops");

    // An allowlisted source skips the preset and the gate.
    set_sanity(SANITY_MARTIAN_SRC, SANITY_MODE_ENFORCE);
    struct pkt martian = tcp4("127.0.0.9", "192.0.2.1", 40000, 443, 0x02, 5);
    CHECK(run(martian) == XDP_DROP, "allowlist: martian drops before");

    lpm_trie_key_t key = {.prefix_len = 8};
    inet_pton(AF_INET, "127.0.0.0", &key.data);
    u64 value = 0;
    bpf_map_update_elem(map_allow, &key, &value, BPF_ANY);
    CHECK(run(martian) == XDP_PASS, "allowlist: an allowlisted martian source passes");

    key.prefix_len = 32;
    inet_pton(AF_INET, "198.51.100.7", &key.data);
    bpf_map_update_elem(map_allow, &key, &value, BPF_ANY);
    set_sanity(SANITY_PORT_GATE_UDP, SANITY_MODE_ENFORCE);
    CHECK(run(udp4("198.51.100.7", "192.0.2.1", 5000, 53)) == XDP_PASS, "allowlist: an allowlisted source skips the port gate");
    CHECK(run(udp4("198.51.100.8", "192.0.2.1", 5000, 53)) == XDP_DROP, "allowlist: another source is still gated");

    set_sanity(SANITY_REASONS, SANITY_MODE_OFF);
}

static int map_fd(struct bpf_object* obj, const char* name)
{
    struct bpf_map* map = bpf_object__find_map_by_name(obj, name);

    if (!map)
    {
        printf("map %s not found\n", name);
        exit(2);
    }

    return bpf_map__fd(map);
}

int main(int argc, char** argv)
{
    const char* path = argc > 1 ? argv[1] : "build/test/xdp_prog.o";

    ncpus = libbpf_num_possible_cpus();

    struct bpf_object* obj = bpf_object__open_file(path, NULL);

    if (!obj)
    {
        printf("cannot open %s\n", path);
        return 2;
    }

    struct bpf_program* prog = bpf_object__find_program_by_name(obj, "xdp_prog_main");

    if (!prog)
    {
        printf("xdp_prog_main not found\n");
        return 2;
    }

    bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

    int ret = bpf_object__load(obj);

    if (ret != 0)
    {
        printf("the verifier refused the program (%d)\n", ret);
        return 2;
    }

    printf("loaded %s: the verifier accepted xdp_prog_main\n", path);

    prog_fd = bpf_program__fd(prog);
    map_filters = map_fd(obj, "map_filters");
    map_filter_active = map_fd(obj, "map_filter_active");
    map_filter_stats = map_fd(obj, "map_filter_stats");
    map_sanity = map_fd(obj, "map_sanity");
    map_sanity_stats = map_fd(obj, "map_sanity_stats");
    map_port_gate = map_fd(obj, "map_port_gate");
    map_local_addr = map_fd(obj, "map_local_addr");
    map_allow = map_fd(obj, "map_allow");

    test_filters();
    test_flip();
    test_sanity();

    printf("%d checks, %d failed\n", checks, failures);

    bpf_object__close(obj);

    return failures ? 1 : 0;
}
