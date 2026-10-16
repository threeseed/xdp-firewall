#pragma once

#include <xdp/libxdp.h>

#include  <common/all.h>

#include <loader/utils/config.h>
#include <loader/utils/helpers.h>

#define XDP_OBJ_PATH "/etc/xdpfw/xdp_prog.o"
#define XDP_MAP_PIN_DIR "/sys/fs/bpf/xdpfw"

int get_map_fd(struct xdp_program *prog, const char *map_name);
void set_libbpf_log_mode(int silent);

struct xdp_program *load_bpf_obj(const char *file_name);
struct bpf_object* get_bpf_obj(struct xdp_program* prog);

int attach_xdp(struct xdp_program *prog, char** mode, int ifidx, int detach, int force_skb, int force_offload);

int delete_filter(int map_filters, u32 idx);
void delete_filters(int map_filters);

int update_filter(int map_filters, filter_rule_cfg_t* filter, int idx);
void update_filters(int map_filters, config__t *cfg);
filter_rule_cfg_t* get_filter_by_slot(config__t* cfg, int slot);

int pin_bpf_map(struct bpf_object* obj, const char* pin_dir, const char* map_name);
int unpin_bpf_map(struct bpf_object* obj, const char* pin_dir, const char* map_name);
int get_map_fd_pin(const char* pin_dir, const char* map_name);

int delete_block(int map_block, u32 ip);
int add_block(int map_block, u32 ip, u64 expires);

int delete_block6(int map_block6, u128 ip);
int add_block6(int map_block6, u128 ip, u64 expires);

int delete_range_drop(int map_range_drop, u32 net, u8 cidr);
int add_range_drop(int map_range_drop, u32 net, u8 cidr);
void update_range_drops(int map_range_drop, int map_range_drop6, config__t* cfg);

int delete_range_drop6(int map_range_drop6, const u32* net, u8 cidr);
int add_range_drop6(int map_range_drop6, const u32* net, u8 cidr);

int delete_allow(int map_allow, u32 net, u8 cidr);
int add_allow(int map_allow, u32 net, u8 cidr);
int delete_allow6(int map_allow6, const u32* net, u8 cidr);
int add_allow6(int map_allow6, const u32* net, u8 cidr);
void update_allow_ranges(int map_allow, int map_allow6, config__t* cfg);

u128 ip6_to_block_key(const struct in6_addr* addr);