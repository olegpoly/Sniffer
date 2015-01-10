#ifndef FATHER_PROTOCOL_H
#define FATHER_PROTOCOL_H

#include <vector>

#include "protocol.h"
#include "ip_protocol_headers.h"
#include "protocols_headers.h"
#include "decoder.h"

// THis class is a base class for protocols
// that may have a next-layer protocol
// The abstract function's purpouse is to
// return a ProtocolNumber value indicating 
// type of the next-layer protocol

class FatherProtockol : public Protocol {
  public:
    virtual ProtocolsNumber GetNextLevelProtocol() const = 0;
};


// Class for the IP v4 protocol.
class IPv4protocol : public FatherProtockol {
  public:
    explicit IPv4protocol(const char* buffer);
    virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
    virtual ProtocolsNumber GetNextLevelProtocol() const;
    static int GetPacketCounter();

  private:
    static int recieved_packets_counter;
    const IPv4header* ip_header_;
    IPv4protocol(const IPv4protocol&);
    void operator=(const IPv4protocol&);
};

// Class for the IP v6 protocol.
class IPv6protocol : public FatherProtockol {
  public:
    explicit IPv6protocol(const char* buffer);
    virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
    virtual ProtocolsNumber GetNextLevelProtocol() const;
    static int GetPacketCounter();

  private:
    void PrintFixedHeader(const IPv6FixedHeader* header, 
                          std::ofstream* file) const;
    void PrintHopByHopHeader(const IPv6HopByHopHeader* header, 
                             std::ofstream* file) const;
    void PrintDestinationHeader(const IPv6DestinationHeader* header, 
                                std::ofstream* file) const;
    void PrintRoutingHeader(const IPv6RoutingHeader* header, 
                            std::ofstream* file) const;
    void PrintFragmentHeader(const IPv6FragmentHeader* header, 
                             std::ofstream* file) const;
    static int recieved_packets_counter;
    const char* packet_buffer_;
    std::vector<Ipv6NextHeaderValue> headers_;
    ProtocolsNumber next_level_protocol;
    IPv6protocol(const IPv6protocol&);
    void operator=(const IPv6protocol&);
};

// Class for the TCP protocol.
class TCPprotocol : public FatherProtockol {
  public:
    explicit TCPprotocol(const char* buffer);
    virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
    virtual ProtocolsNumber GetNextLevelProtocol() const;
    static int GetPacketCounter();

  private:
    static int recieved_packets_counter;
    const TCPHeader* tcp_header_;
    TCPprotocol(const TCPprotocol&);
    void operator=(const TCPprotocol&);
};

// Class for the UDP protocol.
class UDPprotocol : public FatherProtockol {
  public:
    explicit UDPprotocol(const char* buffer);
    virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
    virtual ProtocolsNumber GetNextLevelProtocol() const;
    static int GetPacketCounter();

  private:
    static int recieved_packets_counter;
    const UDPHeader* udp_header_;
    UDPprotocol(const UDPprotocol&);
    void operator=(const UDPprotocol&);
};

#endif  // FATHER_PROTOCOL_H

