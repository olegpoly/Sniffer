//  Copyright 2014 Oleh Chernygevych

#ifndef NETWROK_NODE_H_
#define NETWROK_NODE_H_

#include "socket.h"

// Stores all nececery variables and functions for network sniffing.
// It is used in SnifferProcessor for recieving a packet
// To use this class create an object and call GetPacket function
class NetworkSniffer {
  public:
    NetworkSniffer();
    ~NetworkSniffer();
    const char* GetPacket();

  private:
    void DetermineLocalIP(char** local_ip);
    void BindSnifferToLocalIp();
    Socket* sniffer_socket_;
    const int kSize_;
    char* buffer_;
    NetworkSniffer(const NetworkSniffer&);
    void operator=(const NetworkSniffer&);
};

#endif


