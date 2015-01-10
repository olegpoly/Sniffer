//  Copyright 2014 Oleh Chernygevych

#include "network_sniffer.h"
#include "socket.h"

#ifdef _WIN32 || _WIN64
#include <winsock2.h>
#include <Mstcpip.h>
#include <Windows.h>
#elif defined __linux__
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <termios.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <limits.h>  // HOST_NAME_MAX
#include <string.h>
#endif

#include <stdio.h>

// Creates socket for sniffing in constructor.
NetworkSniffer::NetworkSniffer()
               : kSize_(1500) {  // 1500-byte packet is the largest allowed by Ethernet
#ifdef __linux__
    sniffer_socket_ = new Socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#elif defined _WIN32 || _WIN64
    //Create a RAW Socket
    sniffer_socket_ = new Socket(AF_INET, SOCK_RAW, IPPROTO_IP);
#endif

    sniffer_socket_->BindSnifferToLocalIp();
    sniffer_socket_->MakeSocketNonBlocking();

    buffer_ = new char[kSize_];  // buffer for recieved messages
    memset(buffer_, 0, kSize_);
}

NetworkSniffer::~NetworkSniffer() {
    delete sniffer_socket_;
    delete[] buffer_;
}

// The GetPacket function recieves a packet a returns it to the caller.
const char* NetworkSniffer::GetPacket() {
    bool success = sniffer_socket_->Recieve(&buffer_, kSize_);
    if (success == true) {
        return buffer_;
    } else {
        return false;
    }
}


