#ifndef DECODER_H_
#define DECODER_H_

#include <vector>
#include "protocol.h"
#include "ip_protocol_headers.h"

enum IPversion {
    IPversion_4 = 4, IPversion_6 = 41, kInvalidIPVersion = -1
};

// The purpose of this class is to perform operations of decoding packet,
// determining it's type and finding some specific field or area in it.
// THis class is used in Protocol classes (TCPprotocol, etc) constructors
// and may be used in other classes that needs to find data in raw
// packet data.
class PacketDecoder {
  public:
    PacketDecoder();
    void DecodeIpv6Header(const char* ipv6_header_begining,  // IN
                          std::vector<Ipv6NextHeaderValue>* ipv6_headers) const;  // OUT
    ProtocolsNumber GetIPv6NextLayerProtocol(const char* ipv6_header_begining,  // IN
                                             char** next_layer_protocol) const;  // OUT
    ProtocolsNumber GetIPv4NextLayerProtocol(const char* ipv4_header_begining,   // IN
                                             char** next_layer_protocol) const;  // OUT
    const ICMPheader* FindICMPHeaderInPacket(const char* packet_buffer) const;
    const DNSHeader* FindDNSHeaderInPacket(const char* packet_buffer) const;
    const TCPHeader* FindTCPHeaderInPacket(const char* packet_buffer) const;
    const UDPHeader* FindUDPHeaderInPacket(const char* packet_buffer) const;
    IPversion DetermineIPversion(const char* ip_header) const;
private:
    PacketDecoder(const PacketDecoder&);
    void operator=(const PacketDecoder&);
};

#endif  // DECODER_H_
