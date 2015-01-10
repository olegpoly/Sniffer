#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include <fstream>

#include "protocols_headers.h"

// Defines constants for all supported protocols
enum ProtocolsNumber {
	kInvalid = -1, kTCP = 6, kUDP = 17, kIP_v4 = 4, kIP_v6 = 41, 
        kDNS = 53, kICMP = 1
};

// All protocol classes use this class as a base, directly ot indirectly
// It decalares function, the porpouse of which is to write specific info
// about protocol header into file.
// For a protocol class: inherit this class directly if it can not have an 
// upper layer protocol, for example DNS, HTCP, etc.
// Otherwise inherit from the "FatherProtocol" class, that is inherited 
// form the Porotocol class too
class Protocol {
  public:
	virtual void PrintHeaderInfoIntoFile(std::ofstream *file) const = 0;
	virtual ~Protocol();
};

// Class for the ICMP protocol.
class ICMPprotocol : public Protocol {
  public:
	explicit ICMPprotocol(const char* buffer);
	virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
	static int GetPacketCounter();

  private:
	static int recieved_packets_counter;
	const ICMPheader* icmp_header_;
	ICMPprotocol(const ICMPprotocol&);
	void operator=(const ICMPprotocol&);
};

// Class for the DNS protocol.
class DNSprotocol : public Protocol {
  public:
	explicit DNSprotocol(const char* buffer);
	virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
	static int GetPacketCounter();

  private:
	static int recieved_packets_counter;
	const DNSHeader* dns_header_;
	DNSprotocol(const DNSprotocol&);
	void operator=(const DNSprotocol&);
};

#endif  // PROTOCOL_H_

