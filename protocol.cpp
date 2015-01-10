#include "protocol.h"
#include "ip_protocol_headers.h"
#include "decoder.h"

#ifdef __linux__
#include <netinet/if_ether.h>
#endif

int ICMPprotocol::recieved_packets_counter = 0;
int DNSprotocol::recieved_packets_counter = 0;

Protocol::~Protocol() {}

//  **** ICMP ****

// takes a pointer to a recevied message and finds ICMP header in it.
ICMPprotocol::ICMPprotocol(const char* packet_buffer) {
    if (packet_buffer != NULL) {
        recieved_packets_counter++;
        PacketDecoder decoder;

#ifdef _WIN32 || _WIN64
        icmp_header_ = decoder.FindICMPHeaderInPacket(packet_buffer);
#elif defined __linux__
        icmp_header_ = decoder.FindICMPHeaderInPacket(packet_buffer + 
                                                      sizeof(ethhdr));
#endif
    } else {
        icmp_header_ = NULL;
    }
}

int ICMPprotocol::GetPacketCounter() {
    return recieved_packets_counter;
}

// Print icmp header information to the logging file
void ICMPprotocol::PrintHeaderInfoIntoFile(std::ofstream* file) const {
    if (file == NULL || file->is_open() == false)
        return;

    if (icmp_header_ == NULL)
        return;

    *file << "### ICMP PROTOCOL HEADER ###\n";

    *file << "error id: ";
    *file << ntohs(icmp_header_->id);
    *file << '\n';

    *file << "error code: ";
    *file << ntohs(icmp_header_->code);
    *file << '\n';

    *file << "checksum: ";
    *file << ntohs(icmp_header_->checksum);
    *file << '\n';

    file->flush();
}

//  **** DNS ****

// takes a pointer to a recevied message and finds dns header in it.
DNSprotocol::DNSprotocol(const char* packet_buffer) {
    if (packet_buffer != NULL) {
        recieved_packets_counter++;
        PacketDecoder decoder;

#ifdef _WIN32 || _WIN64
        dns_header_ = decoder.FindDNSHeaderInPacket(packet_buffer);
#elif defined __linux__
        dns_header_ = decoder.FindDNSHeaderInPacket(packet_buffer +
                                                    sizeof(ethhdr));
#endif
    } else {
        dns_header_ = NULL;
    }
}

int DNSprotocol::GetPacketCounter() {
    return recieved_packets_counter;
}

// Print DNS header information to the logging file
void DNSprotocol::PrintHeaderInfoIntoFile(std::ofstream* file) const {
    if (file == NULL || file->is_open() == false)
        return;

    if (dns_header_ == NULL)
        return;

    *file << "### DNS PROTOCOL HEADER ###\n";

    *file << "message id: ";
    *file << ntohs(dns_header_->id);
    *file << '\n';

    *file << "answers count: ";
    *file << ntohs(dns_header_->answers);
    *file << '\n';

    *file << "questions count: ";
    *file << ntohs(dns_header_->questions);
    *file << '\n';

    file->flush();
}

