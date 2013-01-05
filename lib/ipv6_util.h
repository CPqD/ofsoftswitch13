#ifndef IPV6_UTIL_H
#define IPV6_UTIL_H 1

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include "util.h"
#include <unistd.h>


#define IN6ADDR_EXACT_INIT { { { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, \
                                  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff } } }
                                  
#define IN6ADDR_ZERO_INIT { { { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
                                  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 } } }
                                  
extern const struct in6_addr in6addr_exact;

static inline bool ipv6_addr_equals(const struct in6_addr *a,
                                    const struct in6_addr *b)
{
#ifdef IN6_ARE_ADDR_EQUAL
    return IN6_ARE_ADDR_EQUAL(a, b);
#else
    return !memcmp(a, b, sizeof(*a));
#endif
}

static inline bool ipv6_mask_is_exact(const struct in6_addr *mask) {
    return ipv6_addr_equals(mask, &in6addr_exact);
}

int
str_to_ipv6(const char *str_, struct in6_addr *addrp, struct in6_addr *maskp);


#endif
