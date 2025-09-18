#include "reservedip.h"
#include <algorithm>
#include <iostream>

// IPv4 reserved ranges (reduced set - excluding stdlib-covered ranges)
// Each range is represented as [start_ip, end_ip] in host byte order
struct IPv4Range {
    uint32_t start;
    uint32_t end;
};

// IPv4 reserved ranges in ascending order for binary search
static const IPv4Range ipv4_reserved_ranges[] = {
    {0x00000000, 0x00FFFFFF},   // 0.0.0.0/8 - Current network
    {0x64400000, 0x647FFFFF},   // 100.64.0.0/10 - Shared address space (carrier-grade NAT)
    {0xC0000000, 0xC0000007},   // 192.0.0.0/29 - IPv4 special purpose
    {0xC0000200, 0xC00002FF},   // 192.0.2.0/24 - TEST-NET-1
    {0xC0586300, 0xC05863FF},   // 192.88.99.0/24 - 6to4 relay anycast
    {0xC6120000, 0xC613FFFF},   // 198.18.0.0/15 - Network benchmarking
    {0xC6336400, 0xC63364FF},   // 198.51.100.0/24 - TEST-NET-2
    {0xCB007100, 0xCB0071FF},   // 203.0.113.0/24 - TEST-NET-3
    {0xE0000000, 0xFFFFFFFF},   // 224.0.0.0/3 - Multicast addresses
};

static const int ipv4_ranges_count = sizeof(ipv4_reserved_ranges) / sizeof(IPv4Range);

// IPv6 reserved prefixes (reduced set - excluding stdlib-covered ranges)
struct IPv6Prefix {
    uint8_t prefix[16];
    uint8_t prefix_len;
};

static const IPv6Prefix ipv6_reserved_prefixes[] = {
    // ::/128 - IPv6 unspecified address
    {{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 128},
    
    // ::ffff:0:0/96 - IPv4-mapped addresses
    {{0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0,0,0,0}, 96},
    
    // 100::/64 - Discard prefix
    {{0x01,0x00,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 64},
    
    // 2001::/32 - Teredo tunneling
    {{0x20,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 32},
    
    // 2001:10::/28 - ORCHID (old)
    {{0x20,0x01,0x00,0x10,0,0,0,0,0,0,0,0,0,0,0,0}, 28},
    
    // 2001:20::/28 - ORCHIDv2  
    {{0x20,0x01,0x00,0x20,0,0,0,0,0,0,0,0,0,0,0,0}, 28},
    
    // 2001:db8::/32 - Documentation example addresses
    {{0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0}, 32},
    
    // ff00::/8 - IPv6 multicast addresses
    {{0xFF,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 8},
};

static const int ipv6_prefixes_count = sizeof(ipv6_reserved_prefixes) / sizeof(IPv6Prefix);

// Check if IPv6 address matches a prefix
static int ipv6_matches_prefix(const uint8_t* ip, const IPv6Prefix* prefix) {
    int bytes_to_check = prefix->prefix_len / 8;
    int remaining_bits = prefix->prefix_len % 8;
    
    // Check complete bytes
    for (int i = 0; i < bytes_to_check; i++) {
        if (ip[i] != prefix->prefix[i]) {
            return 0;
        }
    }
    
    // Check remaining bits if any
    if (remaining_bits > 0) {
        uint8_t mask = 0xFF << (8 - remaining_bits);
        if ((ip[bytes_to_check] & mask) != (prefix->prefix[bytes_to_check] & mask)) {
            return 0;
        }
    }
    
    return 1;
}

extern "C" {

int IsReservedIPv4(uint32_t ip_host) {
    // Binary search through sorted ranges
    int left = 0;
    int right = ipv4_ranges_count - 1;
    
    while (left <= right) {
        int mid = (left + right) / 2;
        const IPv4Range* range = &ipv4_reserved_ranges[mid];
        
        if (ip_host >= range->start && ip_host <= range->end) {
            return 1; // Found in range
        } else if (ip_host < range->start) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    
    return 0; // Not found in any range
}

int IsReservedIPv6(const uint8_t* ip16) {
    if (ip16 == nullptr) {
        return 0;
    }
    
    // Linear scan through IPv6 prefixes (small list)
    for (int i = 0; i < ipv6_prefixes_count; i++) {
        if (ipv6_matches_prefix(ip16, &ipv6_reserved_prefixes[i])) {
            return 1;
        }
    }
    
    return 0;
}

}
