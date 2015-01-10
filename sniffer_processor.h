// Copyright 2014 Oleh Chernygevych

#ifndef SNIFFERPROCESSOR_H_
#define SNIFFERPROCESSOR_H_

#include "sniffer_io.h"
#include "network_sniffer.h"
#include "socket.h"
#include "filter.h"

// Main class of this application.
// Operates and coordinates other classes.
// In order to start network sniffing call Sniff function
class SnifferProcessor {
  public:
    SnifferProcessor();
    ~SnifferProcessor();
    void Sniff();
	char* SetUserFileName(const char* file_name);
    Filter* GetProtocolFilter();

  private:
#ifdef _WIN32 || _WIN64
    void StopSniffer();
#elif defined __linux__
    static void* StopSniffer(void* continue_sniffing);
#endif
    void PrintProtocolCounters() const;
    bool continue_sniffing_;
    SnifferIO* io_system_;
    NetworkSniffer* sniffer_;
    const char* default_file_name_;
    char* user_file_name_;
    Filter* protocol_filter_;
    SnifferProcessor(const SnifferProcessor&);
    void operator=(const SnifferProcessor&);
};

#endif  // SNIFFERPROCESSOR_H_


