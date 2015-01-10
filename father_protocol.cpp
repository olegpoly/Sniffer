#include "father_protocol.h"
#include "decoder.h"

// Initialezes local variables
int IPv4protocol::recieved_packets_counter = 0;
int IPv6protocol::recieved_packets_counter = 0;
int TCPprotocol::recieved_packets_counter = 0;
int UDPprotocol::recieved_packets_counter = 0;

#ifdef __linux__
#include <netinet/if_ether.h>
#include <string.h>
#include <arpa/inet.h>
#endif 

//  **** IP v4 ****

// takes a pointer to a received message and finds ip header in it.
IPv4protocol::IPv4protocol(const char *buffer) {
    if (buffer != NULL) {
        recieved_packets_counter++;
        PacketDecoder decoder;

        if (decoder.DetermineIPversion(buffer) != IPversion_6) {
            // Get network layer header
#ifdef __linux__
            ip_header_ = reinterpret_cast<const IPv4header*>(buffer + 
                                                           sizeof(struct ethhdr));
#elif defined _WIN32 || _WIN64  // __linux__
            ip_header_ = reinterpret_cast<const IPv4header*>(buffer);
#endif  // _WIN32 || _WIN64
        }
    } else {
        ip_header_ = NULL;
    }
}

int IPv4protocol::GetPacketCounter() {
    return recieved_packets_counter;
}

// Takes a pointer to an ofstream object and writes information
// about ip header into file
void IPv4protocol::PrintHeaderInfoIntoFile(std::ofstream* file) const {
    if (file == NULL || file->is_open() == false)
        return;

    if (ip_header_ == NULL)
        return;

    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header_->source_address;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_header_->destination_address;

    *file << "### IP PROTOCOL HEADER ###\n";

    *file << "source address: ";
    *file << inet_ntoa(source.sin_addr);
    *file << '\n';

    *file << "destination address: ";
    *file << inet_ntoa(dest.sin_addr);
    *file << '\n';

    *file << "header length: ";
    *file << ntohs(ip_header_->header_length);
    *file << '\n';

    *file << "checksum: ";
    *file << ntohs(ip_header_->checksum);
    *file << '\n';

    file->flush();
}


// Retuns upper-layer protocol used in the current message
ProtocolsNumber IPv4protocol::GetNextLevelProtocol() const {
    return static_cast<ProtocolsNumber>(ip_header_->transport_protocol);
}

//  **** IP v6 ****

// takes a pointer to a received message and finds ip header in it.
IPv6protocol::IPv6protocol(const char *packet_buffer) {
    if (packet_buffer != NULL) {
        recieved_packets_counter++;
        PacketDecoder decoder;
        char* next_layer_protocol = NULL;

#ifdef _WIN32 || _WIN64
        decoder.DecodeIpv6Header(packet_buffer, &headers_);
        next_level_protocol = decoder.GetIPv6NextLayerProtocol(packet_buffer, 
                                                               &next_layer_protocol);
#elif defined __linux__
        decoder.DecodeIpv6Header(packet_buffer + sizeof(ethhdr), &headers_);
        next_level_protocol = decoder.GetIPv6NextLayerProtocol(packet_buffer + 
                                                               sizeof(ethhdr), 
                                                               &next_layer_protocol);
#endif

        packet_buffer_ = packet_buffer;
    }
}

int IPv6protocol::GetPacketCounter() {
    return recieved_packets_counter;
}

// Takes a pointer to an ofstream object and writes information
// about ip header into file
void IPv6protocol::PrintHeaderInfoIntoFile(std::ofstream* file) const {
    if (file == NULL || file->is_open() == false)
        return;

    if (headers_.size() == 0)
        return;

    *file << "### IP v6 PROTOCOL HEADERS ###\n";

    const char* buffer = packet_buffer_;

    for (std::vector<Ipv6NextHeaderValue>::iterator headers_iterator; headers_iterator != headers_.end(); ++headers_iterator)
        switch (*headers_iterator) {
          case kIPv6: {
            const IPv6FixedHeader* fixed_header = reinterpret_cast<const IPv6FixedHeader*>(buffer);
            buffer += 40;
            PrintFixedHeader(fixed_header, file);
            break;
          }
          case kHopByHop: {
            const IPv6HopByHopHeader* hop_by_hop_header = reinterpret_cast<const IPv6HopByHopHeader*>(buffer);
            buffer += hop_by_hop_header->length;
            PrintHopByHopHeader(hop_by_hop_header, file);
            break;
          }
          case kDestinationOptins: {
            const IPv6DestinationHeader* destination_header = reinterpret_cast<const IPv6DestinationHeader*>(buffer);
            buffer += destination_header->length;
            PrintDestinationHeader(destination_header, file);
            break;
          }
          case kRoutingHeader: {
            const IPv6RoutingHeader* routing_header = reinterpret_cast<const IPv6RoutingHeader*>(buffer);
            buffer += routing_header->length;
            PrintRoutingHeader(routing_header, file);
            break;
          }
          case kFragmentHeader: {
            const IPv6FragmentHeader* fragment_header = reinterpret_cast<const IPv6FragmentHeader*>(buffer);
            buffer += sizeof (IPv6FragmentHeader);
            PrintFragmentHeader(fragment_header, file);
            break;
          }
          default: {
            break;
          }
        }
}

// Print Fixed ipv6 header information to the logging file
void IPv6protocol::PrintFixedHeader(const IPv6FixedHeader* header, std::ofstream* file) const {
    struct sockaddr_in6 source, dest;
    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));

    // Write addresses to sockeaddr_in76 structures
    // so it could be later used to convert ip address
    // into readable form

#ifdef _WIN32 || _WIN64
    source.sin6_addr.u = header->source.u;
    dest.sin6_addr.u = header->destination.u;
#elif defined __linux__
    source.sin6_addr = header->source;
    dest.sin6_addr = header->destination;
#endif

    *file << "IP v6 Fixed header\n";
    *file << "------------------\n";

    char ipv6_address_string[INET6_ADDRSTRLEN];

    // Print source address
    inet_ntop(AF_INET6, &(source.sin6_addr), ipv6_address_string, INET6_ADDRSTRLEN);
    *file << "source address: ";
    *file << ipv6_address_string;
    *file << '\n';

    // Print destination address
    inet_ntop(AF_INET6, &(dest.sin6_addr), ipv6_address_string, INET6_ADDRSTRLEN);
    *file << "destination address: ";
    *file << ipv6_address_string;
    *file << '\n';

    *file << "hop limit: ";
    *file << ntohs(header->ip6_ctlun.ip6_un1.hop_limit);
    *file << '\n';

    file->flush();
}

// Print Fixed ipv6 header information to the logging file
void IPv6protocol::PrintHopByHopHeader(const IPv6HopByHopHeader* header, 
                                       std::ofstream* file) const {
    *file << "IP v6 HopByHop header\n";
    *file << "------------------\n";

    *file << "header length: ";
    *file << ntohs(header->length);
    *file << '\n';
}

// Print Destination ipv6 header information to the logging file
void IPv6protocol::PrintDestinationHeader(const IPv6DestinationHeader* header, 
                                          std::ofstream* file) const {
    *file << "IP v6 HopByHop header\n";
    *file << "------------------\n";

    *file << "header length: ";
    *file << ntohs(header->length);
    *file << '\n';
}

// Print Routing ipv6 header information to the logging file
void IPv6protocol::PrintRoutingHeader(const IPv6RoutingHeader* header, 
                                      std::ofstream* file) const {
    *file << "IP v6 HopByHop header\n";
    *file << "------------------\n";

    *file << "header length: ";
    *file << ntohs(header->length);
    *file << '\n';

    *file << "segments left: ";
    *file << ntohs(header->segments_left);
    *file << '\n';

    *file << "type: ";
    *file << ntohs(header->type);
    *file << '\n';
}

// Print Fragmen ipv6 header information to the logging file
void IPv6protocol::PrintFragmentHeader(const IPv6FragmentHeader* header, 
                                       std::ofstream* file) const {
    *file << "IP v6 HopByHop header\n";
    *file << "------------------\n";

    *file << "identification: ";
    *file << ntohs(header->identification);
    *file << '\n';

    *file << "offset: ";
    *file << ntohs(header->offset);
    *file << '\n';

    *file << "m flag (1 means more fragments follow; 0 means last fragment): ";
    *file << ntohs(header->m);
    *file << '\n';
}

// Retuns upper-layer protocol used in the current message
ProtocolsNumber IPv6protocol::GetNextLevelProtocol() const {
    return next_level_protocol;
}

//  **** TCP ****

// takes a pointer to a recevied message and finds tcp header in it.
TCPprotocol::TCPprotocol(const char *buffer) {
    if (buffer == NULL)
        return;

    recieved_packets_counter++;
    PacketDecoder decoder;

#ifdef __linux__
    tcp_header_ = decoder.FindTCPHeaderInPacket(buffer + sizeof(struct ethhdr));
#elif defined _WIN32 || _WIN64  // __linux__
    tcp_header_ = decoder.FindTCPHeaderInPacket(buffer);
#endif  // _WIN32 || _WIN64
}

int TCPprotocol::GetPacketCounter() {
    return recieved_packets_counter;
}

// Takes a pointer to an ofstream object and writes information
// about tcp header into file
void TCPprotocol::PrintHeaderInfoIntoFile(std::ofstream* file) const {
    if (file == NULL || file->is_open() == false)
        return;

    if (tcp_header_ == NULL)
        return;

    *file << "### TCP PROTOCOL HEADER ###\n";

    *file << "source port: ";
    *file << ntohs(tcp_header_->source);
    *file << '\n';

    *file << "destination port: ";
    *file << ntohs(tcp_header_->destination);
    *file << '\n';

    *file << "header length in DWORDS: ";
    *file << ntohs(tcp_header_->data_offset);
    *file << '\n';

    *file << "header length in BYTES: ";
    *file << ntohs(tcp_header_->data_offset * 4);  // 1 dword = 4 bytes
    *file << '\n';

    *file << "window size (in bytes): ";
    *file << ntohs(tcp_header_->window);
    *file << '\n';

    *file << "checksum: ";
    *file << ntohs(tcp_header_->checksum);
    *file << '\n';

    file->flush();
}

// Retuns upper-layer protocol used in the current message
ProtocolsNumber TCPprotocol::GetNextLevelProtocol() const {
    return kInvalid;  // not implemeted yet
}

//  **** UDP ****

// takes a pointer to a recevied message and finds udp header in it.
UDPprotocol::UDPprotocol(const char *buffer) {
    if (buffer != NULL) {
        recieved_packets_counter++;
        PacketDecoder decoder;

#ifdef __linux__
        udp_header_ = decoder.FindUDPHeaderInPacket(buffer + sizeof(struct ethhdr));
#elif defined _WIN32 || _WIN64  // __linux__
        udp_header_ = decoder.FindUDPHeaderInPacket(buffer);
#endif  // _WIN32 || _WIN64
    } else {
        udp_header_ = NULL;
    }
}

int UDPprotocol::GetPacketCounter() {
    return recieved_packets_counter;
}

ProtocolsNumber UDPprotocol::GetNextLevelProtocol() const {
    int port = ntohs(udp_header_->destination);

    return static_cast<ProtocolsNumber>(port);
}

// Takes a pointer to an ofstream object and writes information
// about udp header into file
void UDPprotocol::PrintHeaderInfoIntoFile(std::ofstream* file) const {
    if (file == NULL || file->is_open() == false)
        return;

    if (udp_header_ == NULL)
        return;

    *file << "### UDP PROTOCOL HEADER ###\n";

    *file << "source port: ";
    *file << ntohs(udp_header_->source);
    *file << '\n';

    *file << "destination port: ";
    *file << ntohs(udp_header_->destination);
    *file << '\n';

    *file << "header length: ";
    *file << ntohs(udp_header_->length);
    *file << '\n';

    *file << "checksum: ";
    *file << ntohs(udp_header_->checksum);
    *file << '\n';

    file->flush();
}

