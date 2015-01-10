#include "decoder.h"

#ifdef __linux__
typedef unsigned char byte;   // 8-bit unsigned entity.
#endif

#define IP_FIXED_HEADER_LENGTH 40

PacketDecoder::PacketDecoder() {}

// Decodes sequence of ipv6 additional headers and stroe the in the actual order
// in "ipv6_headers" vector.
void PacketDecoder::DecodeIpv6Header(const char* ipv6_header_begining,                  // IN
                                     std::vector<Ipv6NextHeaderValue>* ipv6_headers)    // OUT
                                     const {
    if (ipv6_header_begining == NULL) return;
    if (DetermineIPversion(ipv6_header_begining) != IPversion_6) return;
    if (ipv6_headers == NULL) return;
    
    const IPv6FixedHeader* fixed_header = reinterpret_cast<const IPv6FixedHeader*>(ipv6_header_begining);
    ipv6_header_begining += IP_FIXED_HEADER_LENGTH;  // IPv6's fixed header is alwsays 40 bites long
    
    // add kIPv6 value to the vector since it it always the first header
    ipv6_headers->push_back(Ipv6NextHeaderValue::kIPv6);
    // add second header to the vector. It is used in the following switch.
    ipv6_headers->push_back(static_cast<Ipv6NextHeaderValue>(ntohs(fixed_header->ip6_ctlun.ip6_un1.next_header)));
    
    bool continue_loop = true;
    
    // Iterate through all ipv6 protocols presenet in the current 
    // packet
    while (continue_loop) {
        switch (ipv6_headers->back()) {
          case kHopByHop: {
            const IPv6HopByHopHeader* hop_by_hop_header = reinterpret_cast<const IPv6HopByHopHeader*>(ipv6_header_begining);
            ipv6_header_begining += hop_by_hop_header->length;
            ipv6_headers->push_back(static_cast<Ipv6NextHeaderValue>(ntohs(hop_by_hop_header->next_header)));
            break;
          }
          case kDestinationOptins: {
            const IPv6DestinationHeader* destination_header = reinterpret_cast<const IPv6DestinationHeader*>(ipv6_header_begining);
            ipv6_header_begining += destination_header->length;
            ipv6_headers->push_back(static_cast<Ipv6NextHeaderValue>(ntohs(destination_header->next_header)));
            break;
          }
          case kRoutingHeader: {
            const IPv6RoutingHeader* routing_header = reinterpret_cast<const IPv6RoutingHeader*>(ipv6_header_begining);
            ipv6_header_begining += routing_header->length;
            ipv6_headers->push_back(static_cast<Ipv6NextHeaderValue>(ntohs(routing_header->next_header)));
            break;
          }
          case kFragmentHeader: {
            const IPv6FragmentHeader* fragment_header = reinterpret_cast<const IPv6FragmentHeader*>(ipv6_header_begining);
            ipv6_header_begining += sizeof (IPv6FragmentHeader);
            ipv6_headers->push_back(static_cast<Ipv6NextHeaderValue>(ntohs(fragment_header->next_header)));
            break;
          }
          default: {
            ipv6_headers->pop_back();
            continue_loop = false;
            break;
          }
        }  // switch
    }  // while
}

// Returns nex layer protocol in ipv6 packet after ipv6's last additional header
// Writes next layer protocol position to the next_layer_protocol argument
ProtocolsNumber PacketDecoder::GetIPv6NextLayerProtocol(const char* ipv6_header_begining,  // in
                                                        char** next_layer_protocol)         // out
                                                        const {
    if (ipv6_header_begining == NULL) return kInvalid;
    if (next_layer_protocol == NULL) return kInvalid;

    int ip_version = DetermineIPversion(ipv6_header_begining);
    
    // If it is a ipv4 packet return error
    if (ip_version == IPversion_4) {
        return kInvalid;
    }
    
    // set next_layer_protocol to the begging of ipv6 protocol
    // next_layer_protocol is going to be moved to the next
    // ipv6 additional header untill a next layer protocol is
    // reached
    *next_layer_protocol = const_cast<char*>(ipv6_header_begining);
    const IPv6FixedHeader* fixed_header = reinterpret_cast<const IPv6FixedHeader*>(*next_layer_protocol);
    *next_layer_protocol += IP_FIXED_HEADER_LENGTH;
    
    int next_protocol = ntohs(fixed_header->ip6_ctlun.ip6_un1.next_header);
    
    bool continue_loop = true;
    
    // Iterate through packet's ipv6 additional headers
    // untill a next layer protocol is reached
    while (continue_loop) {
        switch (next_protocol) {
          case kHopByHop: {
            const IPv6HopByHopHeader* hop_by_hop_header = reinterpret_cast<const IPv6HopByHopHeader*>(*next_layer_protocol);
            *next_layer_protocol += hop_by_hop_header->length;
            next_protocol = hop_by_hop_header->next_header;
            break;
          }
          case kDestinationOptins: {
            const IPv6DestinationHeader* destination_header = reinterpret_cast<const IPv6DestinationHeader*>(*next_layer_protocol);
            *next_layer_protocol += destination_header->length;
            next_protocol = destination_header->next_header;
            break;
          }
          case kRoutingHeader: {
            const IPv6RoutingHeader* routing_header = reinterpret_cast<const IPv6RoutingHeader*>(*next_layer_protocol);
            *next_layer_protocol += routing_header->length;
            next_protocol = routing_header->next_header;
            break;
          }
          case kFragmentHeader: {
            const IPv6FragmentHeader* fragment_header = reinterpret_cast<const IPv6FragmentHeader*>(*next_layer_protocol);
            *next_layer_protocol += sizeof (IPv6FragmentHeader);
            next_protocol = fragment_header->next_header;
            break;
          }
          default: {
            return static_cast<ProtocolsNumber>(next_protocol);
          }
        }  // switch
    }  // while
}

// Returns next layer protocol in ip4 packet
ProtocolsNumber PacketDecoder::GetIPv4NextLayerProtocol(const char* ipv4_header_begining,  // IN
                                                        char** next_layer_protocol)  // OUT
                                                        const {
    if (ipv4_header_begining == NULL) return kInvalid;
    if (next_layer_protocol == NULL) return kInvalid;

    int ip_version = DetermineIPversion(ipv4_header_begining);
    
    if (ip_version == IPversion_4) {
        const IPv4header* ip_header = reinterpret_cast<const IPv4header*>(ipv4_header_begining);
        *next_layer_protocol = const_cast<char*>(ipv4_header_begining + 
                                                 ip_header->header_length * sizeof(DWORD));
        return static_cast<ProtocolsNumber>(ip_header->transport_protocol);
    }
    
    return kInvalid;
}

// Takes a pointer to ip header and detrmines it's version
IPversion PacketDecoder::DetermineIPversion(const char* ip_header) const {
    if (ip_header == NULL) return kInvalidIPVersion;

    // structure for determining ip version
    struct ipVersion {
        byte unused: 4;
        byte version : 4;
    };
    
    int version = reinterpret_cast<const ipVersion*>(ip_header)->version;
    
    return static_cast<IPversion>(version);
}

// Takes a pointer to ip header and returns a TCP header 
// if there is one
const TCPHeader* PacketDecoder::FindTCPHeaderInPacket(const char* packet_buffer) const {
    if (packet_buffer == NULL) return NULL;

    char* ip_next_layer_protocol = NULL;
    ProtocolsNumber protocol;
    
    if (DetermineIPversion(packet_buffer) == kIPv6) {
        protocol = GetIPv6NextLayerProtocol(packet_buffer, &ip_next_layer_protocol);
    } else {  // IPv4
        protocol = GetIPv4NextLayerProtocol(packet_buffer, &ip_next_layer_protocol);
    }
    
    if (protocol == kTCP) {
        return reinterpret_cast<TCPHeader*>(ip_next_layer_protocol);
    } else {
        return NULL;
    }
}

// Takes a pointer to ip header and returns a UDP header 
// if there is one
const UDPHeader* PacketDecoder::FindUDPHeaderInPacket(const char* packet_buffer) const {
    if (packet_buffer == NULL) return NULL;

    char* ip_next_layer_protocol = NULL;
    ProtocolsNumber protocol;
    
    if (DetermineIPversion(packet_buffer) == kIPv6) {
        protocol = GetIPv6NextLayerProtocol(packet_buffer, &ip_next_layer_protocol);
    } else {  // IPv4
        protocol = GetIPv4NextLayerProtocol(packet_buffer, &ip_next_layer_protocol);
    }
    
    if (protocol == kUDP) {
        return reinterpret_cast<UDPHeader*>(ip_next_layer_protocol);
    } else {
        return NULL;
    }
}

// Takes a pointer to ip header and returns a ICMP header 
// if there is one
const ICMPheader* PacketDecoder::FindICMPHeaderInPacket(const char* packet_buffer) 
                                                        const {
    if (packet_buffer == NULL) return NULL;

    PacketDecoder decoder;
    
    if (decoder.DetermineIPversion(packet_buffer) == IPversion_4) {
        int header_length = reinterpret_cast<const IPv4header*>(packet_buffer)->
                                                                header_length * (sizeof(DWORD));
        return reinterpret_cast<const ICMPheader*>(packet_buffer + header_length);
    }
    
    if (decoder.DetermineIPversion(packet_buffer) == IPversion_6) {
        char* protocol = NULL;
        ProtocolsNumber protocol_next = GetIPv6NextLayerProtocol(packet_buffer, &protocol);
        if (protocol_next == kICMP) {
            return reinterpret_cast<const ICMPheader*>(protocol);
        }
    }
    
    return NULL;
}

// Takes a pointer to ip header and returns a DNS header 
// if there is one
const DNSHeader* PacketDecoder::FindDNSHeaderInPacket(const char* packet_buffer) const {
    if (packet_buffer == NULL) return NULL;

    PacketDecoder decoder;
    
    const TCPHeader* tcp_header = FindTCPHeaderInPacket(packet_buffer);
    
    if (tcp_header != NULL) {
        int tcp_header_length = tcp_header->data_offset * (sizeof(DWORD));
        
        if (tcp_header->destination == kDNS) {
            return reinterpret_cast<const DNSHeader*>(
                        reinterpret_cast<const char*>(tcp_header)+tcp_header_length);
        }
    }
    
    const UDPHeader* udp_header = FindUDPHeaderInPacket(packet_buffer);
    
    if (udp_header != NULL) {
        int udp_header_length = ntohs(udp_header->length);
        int port = ntohs(udp_header->destination);
        const char* udp_header_char_ptr = reinterpret_cast<const char*>(udp_header);
        
        if (port == kDNS) {
            return reinterpret_cast<const DNSHeader*>(udp_header_char_ptr + 
                                                      udp_header_length);
        }
    }
}

