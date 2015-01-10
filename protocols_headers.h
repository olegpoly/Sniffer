// Copyright 2014 Oleh Chernygevych
#ifndef PROTOCOLS_HEADERS_H_
#define PROTOCOLS_HEADERS_H_

// This file consists of headers for protocols
// (all but IP protocols, they are in "ip_protocol_headers.h")
// It is used primarily in protocol classes, since
// all of them have one of these structures as a 
// a private member field to store infor about
// themselves

#include <stdint.h>

typedef unsigned char BYTE;   // 8-bit unsigned entity.
typedef unsigned short USHORT;

// Ethernet header
struct EthernetHeader {
    unsigned char  destination[6];
    unsigned char  source[6];
    uint8_t  upper_protocol; // IP, ARP etc
};

// Dns header
struct DNSHeader {
    short id;
    short flags;
    short questions;
    short answers;
    short name_server_count;
    short additional_recor_count;
};

// Udp header
struct UDPHeader {
    unsigned short source;
    unsigned short destination;
    unsigned short length;
    unsigned short checksum;
};

// TCP header
struct TCPHeader {
    unsigned short source;
    unsigned short destination;
    unsigned int sequence;
    unsigned int acknowledge;

    unsigned char nonce_sum : 1;
    unsigned char reserved_part : 3;
    unsigned char data_offset : 4;  // number of DWORDs

    unsigned char finish : 1;
    unsigned char synchronise : 1;
    unsigned char reset : 1;
    unsigned char push : 1;
    unsigned char acknowledgement : 1;
    unsigned char urgent : 1;
    unsigned char ecn_echo : 1;
    unsigned char congestion_window_reduced : 1;

    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};

// ICMP header
struct ICMPheader
{
    BYTE type;
    BYTE code;
    USHORT checksum;
    USHORT id;
    USHORT sequence;
};

#endif  // PROTOCOLS_HEADERS_H_


