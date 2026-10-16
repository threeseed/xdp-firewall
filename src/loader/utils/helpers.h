#pragma once

#include <common/all.h>

#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <ctype.h>

#include <time.h>

struct ip_range
{
    u32 ip;
    u8 cidr;
} typedef ip_range_t;

struct ip6_range
{
    unsigned int success;

    // The 16 address bytes in network byte order.
    u32 ip[4];

    // Prefix length (128 when no "/len" is given).
    u8 cidr;
} typedef ip6_range_t;

struct port_range
{
    unsigned int success;
    u16 min;
    u16 max;
} typedef port_range_t;

extern int cont;

void print_help_menu();
void hdl_signal(int code);
ip_range_t parse_ip_range(const char* ip);
ip6_range_t parse_ip6_range(const char* ip);
int is_ip6_str(const char* ip);
u32 cidr_to_mask(u8 cidr);
void mask_ip6(u32* ip, u8 cidr);
const char* get_protocol_str_by_id(int id);
void print_tool_info();
u64 get_boot_nano_time();
port_range_t parse_port_range(const char* range_str);