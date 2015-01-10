// Copyright 2014 Oleh Chernygevych

#ifndef SNIFFERIO_H_
#define SNIFFERIO_H_

#include <fstream>
#include "protocol.h"
#include "filter.h"

// Class for file manipulating.
// Used in SnifferProcessor class.
// Writes information about a packet to the log_file_ using LogPacket function.
class SnifferIO {
  public:
    SnifferIO();
    ~SnifferIO();
    bool openFile(const char* fileName);
    void LogPacket(const char* buffer_packet, Filter* protocol_filter) const;

  private:
    void LogProtocol(const Protocol* protocol_to_log) const;
    std::ofstream* log_file_;
    SnifferIO(const SnifferIO&);
    void operator=(const SnifferIO&);
};

#endif  // SNIFFERIO_H_


