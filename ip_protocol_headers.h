// Copyright 2014 Oleh Chernygevych
#ifndef IP_PROTOCOLS_HEADERS_IPv6_H_
#define IP_PROTOCOLS_HEADERS_IPv6_H_

#include <stdint.h>
#ifdef _WIN32 || _WIN64
#include <Ws2tcpip.h>
#elif defined __linux__
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#endif

// This file consists of
// all ip headers structures declarations
// Information to construct these structs
// is taken from RFC 3542 ad 791

// Ip header
struct IPv4header {
    unsigned char header_length : 4;
    unsigned char version : 4;
    unsigned char type_of_service;
    unsigned short total_length;
    unsigned short id;

    unsigned char frag_offset : 5;

    unsigned char more_fragment : 1;
    unsigned char dont_fragment : 1;
    unsigned char reserved_zero : 1;

    unsigned char frag_offset1;

    unsigned char ttl;
    unsigned char transport_protocol;
    unsigned short checksum;
    unsigned int source_address;
    unsigned int destination_address;
};

// IPv6 defines the following new values for the Next Header field.
// For the sake of giving them understandable names "Ipv6Headres" enum is defined

// Possible values according to RFC 3542:
//#define IPPROTO_HOPOPTS   0   /* IPv6 Hop-by-Hop options */
//#define IPPROTO_IPV6     41   /* IPv6 header */
//#define IPPROTO_ROUTING  43   /* IPv6 Routing header */
//#define IPPROTO_FRAGMENT 44   /* IPv6 fragment header */
//#define IPPROTO_ESP      50   /* encapsulating security payload */
//#define IPPROTO_AH       51   /* authentication header */
//#define IPPROTO_ICMPV6   58   /* ICMPv6 */
//#define IPPROTO_NONE     59   /* IPv6 no next header */
//#define IPPROTO_DSTOPTS  60   /* IPv6 Destination options */

enum Ipv6NextHeaderValue {
    kHopByHop = 0, kIPv6 = 41, kRoutingHeader = 43, kFragmentHeader = 44, kEncapsulatingSecurityPayload = 50,
    kAuthentication = 51, kICMPv6 = 58, kNoNextHeader = 59, kDestinationOptins = 60
};

// Ip6 header
struct IPv6FixedHeader {
    union {
        struct ip6_hdrctl {
            uint32_t ip6_un1_flow; /* 4 bits version, 8 bits TC, 20 bits
                                   flow-ID */
            uint16_t payload_length;
            uint8_t  next_header;
            uint8_t  hop_limit;
        } ip6_un1;
        uint8_t ip6_un2_vfc;     /* 4 bits version, top 4 bits
                                 tclass */
    } ip6_ctlun;
    struct in6_addr source;
    struct in6_addr destination;
};

/* Hop-by-Hop options header */
struct IPv6HopByHopHeader {
public:
    uint8_t  next_header;
    uint8_t  length;
    /* followed by options */
};

/* Destination options header */
struct IPv6DestinationHeader {
public:
    uint8_t  next_header;
    uint8_t  length;
    /* followed by options */
};

/* Routing header */
struct IPv6RoutingHeader {
public:
    uint8_t  next_header;
    uint8_t  length;
    uint8_t  type;
    uint8_t  segments_left;
    /* followed by routing type specific data */
};

/* Type 0 Routing header */
class IPv6RoutingType0Header {
public:
    uint8_t  next_header;
    uint8_t  length;
    uint8_t  type;
    uint8_t  segments_left;
    uint32_t reserved_field;
    /* followed by up to 127 struct in6_addr */
};

/* Fragment header */
struct IPv6FragmentHeader {
public:
    uint8_t   next_header;
    uint8_t   reserved_field;
    uint16_t  offset : 13;
    uint16_t  reserver : 2;
    uint16_t  m : 1;  // 1 means more fragments follow; 0 means last fragment
    uint32_t  identification;
};

#endif  // IP_PROTOCOLS_HEADERS_IPv6_H_

