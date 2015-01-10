//  Copyright 2014 Oleh Chernygevych

#include "sniffer_io.h"

#include <errno.h>
#include <stdio.h>

#include <fstream>
#ifdef __linux__
#include <netinet/if_ether.h>
#endif

#include "father_protocol.h"
#include "protocol.h"

SnifferIO::SnifferIO() {
    log_file_ = NULL;
}

SnifferIO::~SnifferIO() {
    if (log_file_ != NULL) {
        log_file_->close();
        delete log_file_;
    }
}

// Opens new file. Retuns true if file has been opened correctly
// and false otherwise
bool SnifferIO::openFile(const char* fileName) {
    if (fileName == NULL)
        return false;

    if (log_file_ != NULL && log_file_->is_open())
        log_file_->close();

    delete log_file_;

    log_file_ = new std::ofstream(fileName, std::ofstream::out);

    return log_file_->is_open();  // true if open, false otherwise
}

// Calls protocol's function "PrintHeaderInfoIntoFile"
void SnifferIO::LogProtocol(const Protocol* protocol_to_log) const {
    if (protocol_to_log != NULL) {
        protocol_to_log->PrintHeaderInfoIntoFile(log_file_);
    }
}

// Logs packet information, all packet's protocols
void SnifferIO::LogPacket(const char* buffer_packet, Filter* protocol_filter) const {
    const FatherProtockol* protockol_low_layer = NULL;
    const Protocol* protockol_ = NULL;
    PacketDecoder decoder;
#ifdef __linux__
    ProtocolsNumber child_protocol = static_cast<ProtocolsNumber>(decoder.DetermineIPversion(buffer_packet + sizeof(ethhdr)));
#elif defined _WIN32 || _WIN64
    ProtocolsNumber child_protocol = static_cast<ProtocolsNumber>(decoder.DetermineIPversion(buffer_packet));
#endif

    // Prints string that identifies new packet in file
    *log_file_ << "\n ***PACKET*** \n";

    bool continueLoop = true;
    while (continueLoop) {
        switch (child_protocol) {
          case kIP_v4: {
            protockol_low_layer = new IPv4protocol(buffer_packet);
            break;
          }
          case kIP_v6: {
            protockol_low_layer = new IPv6protocol(buffer_packet);
            break;
          }
          case kTCP: {
            protockol_low_layer = new TCPprotocol(buffer_packet);
            break;
          }
          case kUDP: {
            protockol_low_layer = new UDPprotocol(buffer_packet);
            break;
          }
          case kDNS: {
            protockol_ = new DNSprotocol(buffer_packet);
            break;
          }
          case kICMP: {
            protockol_ = new ICMPprotocol(buffer_packet);
            break;
          }
          case kInvalid: {
            continueLoop = false;
            continue;
          }
          default: {
            continueLoop = false;
            continue;
          }
        }  // switch

        // Check if protocol is allowed to log in filter
        if (protocol_filter->CheckIfProtocolAllowed(child_protocol) == true) {
            // Log protocol
            if (protockol_ == NULL) {
                LogProtocol(protockol_low_layer);
            } else {
                LogProtocol(protockol_);
            }
        }

        // Get next level protocol id and clean up variables
        if (protockol_low_layer != NULL) {
            child_protocol = protockol_low_layer->GetNextLevelProtocol();
            delete protockol_low_layer;
        }
        if (protockol_ != NULL) {
            // in this protocol don't have upper-layyer prototocol
            child_protocol = kInvalid;
            delete protockol_;
        }

        protockol_low_layer = NULL;
        protockol_ = NULL;
    }  // while

    // Print a string that indentifies end of current packet info
    *log_file_ << "\n ************ \n";
}

