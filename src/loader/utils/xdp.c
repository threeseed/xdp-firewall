#include <loader/utils/xdp.h>

/**
 * Finds a BPF map's FD.
 * 
 * @param prog A pointer to the XDP program structure.
 * @param mapname The name of the map to retrieve.
 * 
 * @return The map's FD.
 */
int get_map_fd(struct xdp_program *prog, const char *map_name)
{
    int fd = -1;

    struct bpf_object *obj = xdp_program__bpf_obj(prog);

    if (obj == NULL)
    {
        fprintf(stderr, "Error finding BPF object from XDP program.\n");

        goto out;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", map_name);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}

/**
 * Custom print function for LibBPF that doesn't print anything (silent mode).
 * 
 * @param level The current LibBPF log level.
 * @param format The message format.
 * @param args Format arguments for the message.
 * 
 * @return void
 */
static int libbpf_silent(enum libbpf_print_level level, const char *format, va_list args)
{
    return 0;
}

/**
 * Sets custom LibBPF log mode.
 * 
 * @param silent If 1, disables LibBPF logging entirely.
 * 
 * @return void
 */
void set_libbpf_log_mode(int silent)
{
    if (silent)
    {
        libbpf_set_print(libbpf_silent);
    }
}

/**
 * Loads a BPF object file.
 * 
 * @param file_name The path to the BPF object file.
 * 
 * @return XDP program structure (pointer) or NULL.
 */
struct xdp_program *load_bpf_obj(const char *file_name)
{
    struct xdp_program *prog = xdp_program__open_file(file_name, "xdp_prog", NULL);

    if (prog == NULL)
    {
        // The main function handles this error.
        return NULL;
    }

    return prog;
}

/**
 * Retrieves BPF object from XDP program.
 * 
 * @param prog A pointer to the XDP program.
 * 
 * @return The BPF object.
 */
struct bpf_object* get_bpf_obj(struct xdp_program* prog)
{
    return xdp_program__bpf_obj(prog);
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param prog A pointer to the XDP program structure.
 * @param mode_used The mode being used.
 * @param ifidx The index to the interface to attach to.
 * @param detach If above 0, attempts to detach XDP program.
 * @param force_skb If set, forces the XDP program to run in SKB mode.
 * @param force_offload If set, forces the XDP program to run in offload mode.
 * 
 * @return 0 on success and 1 on error.
 */
int attach_xdp(struct xdp_program *prog, char** mode, int ifidx, int detach, int force_skb, int force_offload)
{
    int err;

    // Before attaching, set chaining options.
    xdp_program__set_run_prio(prog, XDP_MULTIPROG_PRIORITY);
    xdp_program__set_chain_call_enabled(prog, XDP_MULTIPROG_ACTION, XDP_MULTIPROG_ENABLED);

    u32 attach_mode = XDP_MODE_NATIVE;

    *mode = "DRV/native";

    if (force_offload)
    {
        *mode = "HW/offload";

        attach_mode = XDP_MODE_HW;
    }
    else if (force_skb)
    {
        *mode = "SKB/generic";
        
        attach_mode = XDP_MODE_SKB;
    }

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        if (detach)
        {
            err = xdp_program__detach(prog, ifidx, attach_mode, 0);
        }
        else
        {
            err = xdp_program__attach(prog, ifidx, attach_mode, 0);
        }

        if (err)
        {
            // Decrease mode.
            switch (attach_mode)
            {
                case XDP_MODE_HW:
                    attach_mode = XDP_MODE_NATIVE;
                    *mode = "DRV/native";

                    break;

                case XDP_MODE_NATIVE:
                    attach_mode = XDP_MODE_SKB;
                    *mode = "SKB/generic";

                    break;

                case XDP_MODE_SKB:
                    // Exit loop.
                    exit = 1;

                    *mode = NULL;
                    
                    break;
            }

            // Retry.
            continue;
        }
        
        // Success, so break current loop.
        break;
    }

    // If exit is set to 1 or smode is NULL, it indicates full failure.
    if (exit || *mode == NULL)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Deletes a filter.
 * 
 * @param map_filters The filters BPF map FD.
 * @param key The map_filters key to clear (buffer * MAX_FILTERS + slot).
 * 
 * @return 0 on success or the error value of bpf_map_update_elem().
 */
int delete_filter(int map_filters, u32 key)
{
    // map_filters is an array map, whose elements cannot be deleted (bpf_map_delete_elem() returns -EINVAL).
    // Clear the slot instead; the XDP program stops at the first slot that is not set.
    filter_t filter = {0};

    return bpf_map_update_elem(map_filters, &key, &filter, BPF_ANY);
}

/**
 * Deletes all filters (both buffers).
 * 
 * @param map_filters The filters BPF map FD.
 * 
 * @return void
 */
void delete_filters(int map_filters)
{
    for (u32 i = 0; i < FILTER_BUFFERS * MAX_FILTERS; i++)
    {
        delete_filter(map_filters, i);
    }
}

/**
 * Updates a filter rule.
 * 
 * @param map_filters The filters BPF map FD.
 * @param filter_cfg A pointer to the filter config rule.
 * @param key The map_filters key to write (buffer * MAX_FILTERS + slot).
 * @param stats_idx The map_filter_stats index the filter counts into.
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int update_filter(int map_filters, filter_rule_cfg_t* filter_cfg, u32 key, u32 stats_idx)
{
    filter_t filter = {0};

    filter.set = filter_cfg->set;
    filter.stats_idx = stats_idx;

    // Disabled filters are written too (enabled = 0); the XDP program skips them, so they keep their slot.
    filter.enabled = (filter_cfg->enabled != 0) ? 1 : 0;

    // Shadow filters only count their matches.
    filter.shadow = (filter_cfg->shadow > 0) ? 1 : 0;

    if (filter_cfg->log > -1)
    {
        filter.log = filter_cfg->log;
    }

    if (filter_cfg->action > -1)
    {
        filter.action = filter_cfg->action;
    }

    if (filter_cfg->block_time > -1)
    {
        filter.block_time = filter_cfg->block_time;
    }

#ifdef ENABLE_RL_IP
    if (filter_cfg->ip_pps > -1)
    {
        filter.do_ip_pps = 1;

        filter.ip_pps = (u64) filter_cfg->ip_pps;
    }

    if (filter_cfg->ip_bps > -1)
    {
        filter.do_ip_bps = 1;

        filter.ip_bps = (u64) filter_cfg->ip_bps;
    }
#endif

#ifdef ENABLE_RL_FLOW
    if (filter_cfg->flow_pps > -1)
    {
        filter.do_flow_pps = 1;

        filter.flow_pps = (u64) filter_cfg->flow_pps;
    }

    if (filter_cfg->flow_bps > -1)
    {
        filter.do_flow_bps = 1;

        filter.flow_bps = (u64) filter_cfg->flow_bps;
    }
#endif

    if (filter_cfg->ip.src_ip)
    {
        ip_range_t ip_range = parse_ip_range(filter_cfg->ip.src_ip);

        filter.ip.src_ip = ip_range.ip;
        filter.ip.src_cidr = ip_range.cidr;
    }

    if (filter_cfg->ip.dst_ip)
    {
        ip_range_t ip_range = parse_ip_range(filter_cfg->ip.dst_ip);

        filter.ip.dst_ip = ip_range.ip;
        filter.ip.dst_cidr = ip_range.cidr;
    }

#ifdef ENABLE_IPV6
    // IPv6 addresses accept "addr" (exact, stored as /128) or "addr/len" (prefix match).
    if (filter_cfg->ip.src_ip6)
    {
        ip6_range_t range = parse_ip6_range(filter_cfg->ip.src_ip6);

        if (!range.success)
        {
            fprintf(stderr, "[WARNING] Invalid source IPv6 address '%s' for filter #%u...\n", filter_cfg->ip.src_ip6, (key % MAX_FILTERS) + 1);
        }
        else
        {
            mask_ip6(range.ip, range.cidr);

            memcpy(filter.ip.src_ip6, range.ip, sizeof(filter.ip.src_ip6));
            filter.ip.src_cidr6 = range.cidr;
        }
    }

    if (filter_cfg->ip.dst_ip6)
    {
        ip6_range_t range = parse_ip6_range(filter_cfg->ip.dst_ip6);

        if (!range.success)
        {
            fprintf(stderr, "[WARNING] Invalid destination IPv6 address '%s' for filter #%u...\n", filter_cfg->ip.dst_ip6, (key % MAX_FILTERS) + 1);
        }
        else
        {
            mask_ip6(range.ip, range.cidr);

            memcpy(filter.ip.dst_ip6, range.ip, sizeof(filter.ip.dst_ip6));
            filter.ip.dst_cidr6 = range.cidr;
        }
    }
#endif

    if (filter_cfg->ip.min_ttl > -1)
    {
        filter.ip.do_min_ttl = 1;

        filter.ip.min_ttl = filter_cfg->ip.min_ttl;
    }

    if (filter_cfg->ip.max_ttl > -1)
    {
        filter.ip.do_max_ttl = 1;

        filter.ip.max_ttl = filter_cfg->ip.max_ttl;
    }

    if (filter_cfg->ip.min_len > -1)
    {
        filter.ip.do_min_len = 1;

        filter.ip.min_len = filter_cfg->ip.min_len;
    }

    if (filter_cfg->ip.max_len > -1)
    {
        filter.ip.do_max_len = 1;

        filter.ip.max_len = filter_cfg->ip.max_len;
    }

    if (filter_cfg->ip.tos > -1)
    {
        filter.ip.do_tos = 1;

        filter.ip.tos = filter_cfg->ip.tos;
    }

    if (filter_cfg->tcp.enabled > -1)
    {
        filter.tcp.enabled = filter_cfg->tcp.enabled;
    }

    port_range_t tcp_src_port_range = parse_port_range(filter_cfg->tcp.sport);

    if (tcp_src_port_range.success)
    {
        filter.tcp.do_sport_min = 1;
        filter.tcp.do_sport_max = 1;

        filter.tcp.sport_min = tcp_src_port_range.min;
        filter.tcp.sport_max = tcp_src_port_range.max;
    }

    port_range_t tcp_dst_port_range = parse_port_range(filter_cfg->tcp.dport);

    if (tcp_dst_port_range.success)
    {
        filter.tcp.do_dport_min = 1;
        filter.tcp.do_dport_max = 1;

        filter.tcp.dport_min = tcp_dst_port_range.min;
        filter.tcp.dport_max = tcp_dst_port_range.max;
    }

    if (filter_cfg->tcp.urg > -1)
    {
        filter.tcp.do_urg = 1;

        filter.tcp.urg = filter_cfg->tcp.urg;
    }

    if (filter_cfg->tcp.ack > -1)
    {
        filter.tcp.do_ack = 1;

        filter.tcp.ack = filter_cfg->tcp.ack;
    }

    if (filter_cfg->tcp.rst > -1)
    {
        filter.tcp.do_rst = 1;

        filter.tcp.rst = filter_cfg->tcp.rst;
    }

    if (filter_cfg->tcp.psh > -1)
    {
        filter.tcp.do_psh = 1;

        filter.tcp.psh = filter_cfg->tcp.psh;
    }

    if (filter_cfg->tcp.syn > -1)
    {
        filter.tcp.do_syn = 1;

        filter.tcp.syn = filter_cfg->tcp.syn;
    }

    if (filter_cfg->tcp.fin > -1)
    {
        filter.tcp.do_fin = 1;

        filter.tcp.fin = filter_cfg->tcp.fin;
    }

    if (filter_cfg->tcp.ece > -1)
    {
        filter.tcp.do_ece = 1;

        filter.tcp.ece = filter_cfg->tcp.ece;
    }

    if (filter_cfg->tcp.cwr > -1)
    {
        filter.tcp.do_cwr = 1;

        filter.tcp.cwr = filter_cfg->tcp.cwr;
    }

    if (filter_cfg->udp.enabled > -1)
    {
        filter.udp.enabled = filter_cfg->udp.enabled;
    }

    port_range_t udp_src_port_range = parse_port_range(filter_cfg->udp.sport);

    if (udp_src_port_range.success)
    {
        filter.udp.do_sport_min = 1;
        filter.udp.do_sport_max = 1;

        filter.udp.sport_min = udp_src_port_range.min;
        filter.udp.sport_max = udp_src_port_range.max;
    }

    port_range_t udp_dst_port_range = parse_port_range(filter_cfg->udp.dport);

    if (udp_dst_port_range.success)
    {
        filter.udp.do_dport_min = 1;
        filter.udp.do_dport_max = 1;

        filter.udp.dport_min = udp_dst_port_range.min;
        filter.udp.dport_max = udp_dst_port_range.max;
    }

    if (filter_cfg->icmp.enabled > -1)
    {
        filter.icmp.enabled = filter_cfg->icmp.enabled;
    }

    if (filter_cfg->icmp.code > -1)
    {
        filter.icmp.do_code = 1;

        filter.icmp.code = filter_cfg->icmp.code;
    }

    if (filter_cfg->icmp.type > -1)
    {
        filter.icmp.do_type = 1;

        filter.icmp.type = filter_cfg->icmp.type;
    }

    return bpf_map_update_elem(map_filters, &key, &filter, BPF_ANY);
}

/**
 * Updates the filter's BPF map with current config settings.
 * The filters are written to the inactive buffer of map_filters, map_filter_active is flipped to it with one write, then the old buffer is cleared.
 * A packet therefore sees either the old filters or the new ones, never a mix.
 * 
 * @param map_filters The filter's BPF map FD.
 * @param map_filter_active The active buffer BPF map FD (map_filter_active), or -1 to write buffer 0 in place.
 * @param cfg A pointer to the config structure.
 * 
 * @return Void
 */
void update_filters(int map_filters, int map_filter_active, config__t *cfg)
{
    int ret;
    int cur_idx = 0;

    u32 active_key = 0;
    u32 active = 0;

    if (map_filter_active > -1 && bpf_map_lookup_elem(map_filter_active, &active_key, &active) != 0)
    {
        active = 0;
    }

    active &= 1;

    // Write the inactive buffer (or buffer 0 in place without map_filter_active).
    u32 next = (map_filter_active > -1) ? (active ^ 1) : 0;
    u32 base = next * MAX_FILTERS;

    // Add a filter to the filter maps.
    // Set filters are written to consecutive slots (unset config entries are skipped, since the XDP program stops at the first unset slot).
    // Disabled filters are written with enabled = 0 so they keep their slot and the slot numbering matches the order of set filters in the config.
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_rule_cfg_t* filter = &cfg->filters[i];

        if (!filter->set)
        {
            continue;
        }

        // Attempt to update filter (counters by slot: the loader does not keep them across reloads that reorder its config).
        if ((ret = update_filter(map_filters, filter, base + cur_idx, cur_idx)) != 0)
        {
            fprintf(stderr, "[WARNING] Failed to update filter #%d due to BPF update error (%d)...\n", cur_idx, ret);

            continue;
        }

        cur_idx++;
    }

    // Clear the remaining slots so rules removed from the config don't linger.
    for (int i = cur_idx; i < MAX_FILTERS; i++)
    {
        delete_filter(map_filters, base + i);
    }

    if (map_filter_active < 0)
    {
        return;
    }

    // Flip to the new buffer, then clear the old one.
    if ((ret = bpf_map_update_elem(map_filter_active, &active_key, &next, BPF_ANY)) != 0)
    {
        fprintf(stderr, "[WARNING] Failed to switch to the new filters due to BPF update error (%d)...\n", ret);

        return;
    }

    for (int i = 0; i < MAX_FILTERS; i++)
    {
        delete_filter(map_filters, active * MAX_FILTERS + i);
    }
}

/**
 * Retrieves the config filter that a map_filters slot was written from by update_filters().
 * 
 * @param cfg A pointer to the config structure.
 * @param slot The map_filters slot (e.g. filter_id of a filter log event).
 * 
 * @return A pointer to the config filter or NULL if not found.
 */
filter_rule_cfg_t* get_filter_by_slot(config__t* cfg, int slot)
{
    int cur = 0;

    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_rule_cfg_t* filter = &cfg->filters[i];

        if (!filter->set)
        {
            continue;
        }

        if (cur == slot)
        {
            return filter;
        }

        cur++;
    }

    return NULL;
}

/**
 * Pins a BPF map to the file system.
 * 
 * @param obj A pointer to the BPF object.
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return 0 on success or value of bpf_map__pin() on error.
 */
int pin_bpf_map(struct bpf_object* obj, const char* pin_dir, const char* map_name)
{
    struct bpf_map* map = bpf_object__find_map_by_name(obj, map_name);

    if (!map)
    {
        return -1;
    }

    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", XDP_MAP_PIN_DIR, map_name);

    return bpf_map__pin(map, full_path);
}

/**
 * Unpins a BPF map from the file system.
 * 
 * @param obj A pointer to the BPF object.
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return
 */
int unpin_bpf_map(struct bpf_object* obj, const char* pin_dir, const char* map_name)
{
    struct bpf_map* map = bpf_object__find_map_by_name(obj, map_name);

    if (!map)
    {
        return 1;
    }

    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", XDP_MAP_PIN_DIR, map_name);

    return bpf_map__unpin(map, full_path);
}

/**
 * Retrieves a map FD on the file system (pinned).
 * 
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return The map FD or -1 on error.
 */
int get_map_fd_pin(const char* pin_dir, const char* map_name)
{
    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", pin_dir, map_name);

    return bpf_obj_get(full_path);
}

/**
 * Deletes IPv4 address from block map.
 * 
 * @param map_block The block map's FD.
 * @param ip The IP address to remove.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem().
 */
int delete_block(int map_block, u32 ip)
{
    return bpf_map_delete_elem(map_block, &ip);
}

/**
 * Adds an IPv4 address to the block map.
 * 
 * @param map_block The block map's FD.
 * @param ip The IP address to add.
 * @param expires When the block expires (CLOCK_MONOTONIC nanoseconds, as returned by get_boot_nano_time(); 0 = permanent).
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int add_block(int map_block, u32 ip, u64 expires)
{
    return bpf_map_update_elem(map_block, &ip, &expires, BPF_ANY);
}

/**
 * Deletes IPv6 address from block map.
 * 
 * @param map_block6 The block map's FD.
 * @param ip The IP address to remove.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem().
 */
int delete_block6(int map_block6, u128 ip)
{
    return bpf_map_delete_elem(map_block6, &ip);
}

/**
 * Adds an IPv6 address to the block map.
 * 
 * @param map_block6 The block map's FD.
 * @param ip The IP address to add.
 * @param expires When the block expires (CLOCK_MONOTONIC nanoseconds, as returned by get_boot_nano_time(); 0 = permanent).
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int add_block6(int map_block6, u128 ip, u64 expires)
{
    return bpf_map_update_elem(map_block6, &ip, &expires, BPF_ANY);
}

/**
 * Deletes an IPv4 range from the drop map.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param net The network IP.
 * @param cidr The network's CIDR.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem(). 
 */
int delete_range_drop(int map_range_drop, u32 net, u8 cidr)
{
    u32 bit_mask = cidr_to_mask(cidr);
    u32 start = net & bit_mask;

    lpm_trie_key_t key = {0};
    key.prefix_len = cidr;
    key.data = start;

    return bpf_map_delete_elem(map_range_drop, &key);
}

/**
 * Adds an IPv4 range to the drop map.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param net The network IP.
 * @param cidr The network's CIDR.
 * 
 * @return 0 on success or error value of bpf_map_update_elem(). 
 */
int add_range_drop(int map_range_drop, u32 net, u8 cidr)
{
    u32 bit_mask = cidr_to_mask(cidr);
    u32 start = net & bit_mask;

    lpm_trie_key_t key = {0};
    key.prefix_len = cidr;
    key.data = start;

    u64 val = ( (u64)bit_mask << 32 ) | start;

    return bpf_map_update_elem(map_range_drop, &key, &val, BPF_ANY);
}

/**
 * Builds an IPv6 LPM trie key.
 * 
 * @param ip The address (four words, network byte order).
 * @param cidr The prefix length.
 * 
 * @return The key with host bits cleared.
 */
static lpm_trie_key6_t make_lpm_key6(const u32* ip, u8 cidr)
{
    lpm_trie_key6_t key = {0};

    if (cidr > 128)
    {
        cidr = 128;
    }

    key.prefix_len = cidr;
    memcpy(key.data, ip, sizeof(key.data));

    mask_ip6(key.data, cidr);

    return key;
}

/**
 * Deletes an IPv6 range from the IPv6 drop map.
 * 
 * @param map_range_drop6 The IPv6 range drop map's FD.
 * @param net The network address (four words, network byte order).
 * @param cidr The prefix length.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem().
 */
int delete_range_drop6(int map_range_drop6, const u32* net, u8 cidr)
{
    lpm_trie_key6_t key = make_lpm_key6(net, cidr);

    return bpf_map_delete_elem(map_range_drop6, &key);
}

/**
 * Adds an IPv6 range to the IPv6 drop map.
 * 
 * @param map_range_drop6 The IPv6 range drop map's FD.
 * @param net The network address (four words, network byte order).
 * @param cidr The prefix length.
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int add_range_drop6(int map_range_drop6, const u32* net, u8 cidr)
{
    lpm_trie_key6_t key = make_lpm_key6(net, cidr);

    // The value is not read by the XDP program; store the prefix length for readers.
    u64 val = key.prefix_len;

    return bpf_map_update_elem(map_range_drop6, &key, &val, BPF_ANY);
}

/**
 * Adds an IP range string (IPv4 or IPv6, with optional "/len") to the matching LPM map pair.
 * 
 * @param map4 The IPv4 map FD (or -1).
 * @param map6 The IPv6 map FD (or -1).
 * @param range The range string.
 * @param is_drop 1 for the range drop maps (map_range_drop value layout), 0 for the allowlist maps.
 * 
 * @return 0 on success, -1 on a parse error or missing map, or the error value of bpf_map_update_elem().
 */
static int add_range_str(int map4, int map6, const char* range, int is_drop)
{
    if (is_ip6_str(range))
    {
        ip6_range_t t = parse_ip6_range(range);

        if (!t.success || map6 < 0)
        {
            return -1;
        }

        return is_drop ? add_range_drop6(map6, t.ip, t.cidr) : add_allow6(map6, t.ip, t.cidr);
    }

    if (map4 < 0)
    {
        return -1;
    }

    ip_range_t t = parse_ip_range(range);

    return is_drop ? add_range_drop(map4, t.ip, t.cidr) : add_allow(map4, t.ip, t.cidr);
}

/**
 * Updates IP ranges from config file.
 * 
 * @param map_range_drop The IPv4 range drop map's FD (or -1).
 * @param map_range_drop6 The IPv6 range drop map's FD (or -1).
 * @param cfg A pointer to the config file
 * 
 * @return void
 */
void update_range_drops(int map_range_drop, int map_range_drop6, config__t* cfg)
{
    for (int i = 0; i < MAX_IP_RANGES; i++)
    {
        const char* range = cfg->drop_ranges[i];

        if (!range)
        {
            continue;
        }

        if (add_range_str(map_range_drop, map_range_drop6, range, 1) != 0)
        {
            fprintf(stderr, "[WARNING] Failed to add IP drop range '%s'...\n", range);
        }
    }
}

/**
 * Deletes an IPv4 range from the allowlist.
 * 
 * @param map_allow The IPv4 allowlist map's FD.
 * @param net The network IP (network byte order).
 * @param cidr The prefix length.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem().
 */
int delete_allow(int map_allow, u32 net, u8 cidr)
{
    lpm_trie_key_t key = {0};
    key.prefix_len = cidr > 32 ? 32 : cidr;
    key.data = net & cidr_to_mask(cidr);

    return bpf_map_delete_elem(map_allow, &key);
}

/**
 * Adds an IPv4 range to the allowlist.
 * 
 * @param map_allow The IPv4 allowlist map's FD.
 * @param net The network IP (network byte order).
 * @param cidr The prefix length.
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int add_allow(int map_allow, u32 net, u8 cidr)
{
    lpm_trie_key_t key = {0};
    key.prefix_len = cidr > 32 ? 32 : cidr;
    key.data = net & cidr_to_mask(cidr);

    // The value is not read by the XDP program; store the prefix length for readers.
    u64 val = key.prefix_len;

    return bpf_map_update_elem(map_allow, &key, &val, BPF_ANY);
}

/**
 * Deletes an IPv6 range from the allowlist.
 * 
 * @param map_allow6 The IPv6 allowlist map's FD.
 * @param net The network address (four words, network byte order).
 * @param cidr The prefix length.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem().
 */
int delete_allow6(int map_allow6, const u32* net, u8 cidr)
{
    lpm_trie_key6_t key = make_lpm_key6(net, cidr);

    return bpf_map_delete_elem(map_allow6, &key);
}

/**
 * Adds an IPv6 range to the allowlist.
 * 
 * @param map_allow6 The IPv6 allowlist map's FD.
 * @param net The network address (four words, network byte order).
 * @param cidr The prefix length.
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int add_allow6(int map_allow6, const u32* net, u8 cidr)
{
    lpm_trie_key6_t key = make_lpm_key6(net, cidr);

    u64 val = key.prefix_len;

    return bpf_map_update_elem(map_allow6, &key, &val, BPF_ANY);
}

/**
 * Updates the allowlist maps from the config file.
 * 
 * @param map_allow The IPv4 allowlist map's FD (or -1).
 * @param map_allow6 The IPv6 allowlist map's FD (or -1).
 * @param cfg A pointer to the config structure.
 * 
 * @return void
 */
void update_allow_ranges(int map_allow, int map_allow6, config__t* cfg)
{
    for (int i = 0; i < MAX_ALLOW_RANGES; i++)
    {
        const char* range = cfg->allow_ranges[i];

        if (!range)
        {
            continue;
        }

        if (add_range_str(map_allow, map_allow6, range, 0) != 0)
        {
            fprintf(stderr, "[WARNING] Failed to add IP allow range '%s'...\n", range);
        }
    }
}

/**
 * Converts an IPv6 address to the map_block6/map_block6_perm key.
 * 
 * The XDP program memcpy()s the 16 raw source address bytes into its u128 key, so the key is the address bytes in network order, not a numeric (host order) value.
 * 
 * @param addr The address.
 * 
 * @return The key.
 */
u128 ip6_to_block_key(const struct in6_addr* addr)
{
    u128 key = 0;
    memcpy(&key, addr->s6_addr, sizeof(key));

    return key;
}