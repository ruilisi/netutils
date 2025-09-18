#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// IsReservedIPv4 checks if the given IPv4 address (in big-endian uint32 format) is reserved
// Returns 1 if reserved, 0 if not reserved
int IsReservedIPv4(uint32_t ip_be);

// IsReservedIPv6 checks if the given IPv6 address (16-byte array) is reserved  
// Returns 1 if reserved, 0 if not reserved
int IsReservedIPv6(const uint8_t* ip16);

#ifdef __cplusplus
}
#endif