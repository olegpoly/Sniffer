Software design documentation
=============================

Introduction
============

Purpose
-------
| The purpose of the Software Design Document is to deﬁne the detailed design for
| all components of the Sniffer application

Scope
-----
| This project consists of one application that can run on Linux and Windows 
| desktop systems

Use case digram
---------------
| A use case diagram is a representation of a user's interaction with the system.

image:: UseCaseSniffer.png


Components decomposition
========================

Components
----------
| **This application consists of basic components:**

| 1. Cross platform network layer
| 2. Main layer
| 3. Protocols layer

Cross platform network layer:
-----------------------------

| **classes**

Socket
  | Class for socket descriptor
  | and functions that manipulates it
  
NetworkSniffer
  | Stores all nececery variables and functions for network sniffing.

Main layer:
-----------

| **classes**

SnifferProccessor: 
  | Main class of this application.
  | Operates and coordinates other classes.
  | In order to start network sniffing call Sniff function
SnifferIO: 
  | all operations with files
Filter: 
  | stores information allowed/not allowed filters
FilterItem: 
  | stores protocol's name, id and bool field that
  | specifies if filter is allowed for logging or not
ApplicationMenu: 
  | class for console interface
  
Protocols layer:
----------------

| **classes**

Protocol: 
  | Abstract class for all protocols to inherit
  | Declares abstract function that prints protocol information
  | to the logging file. All class that can't have a next-layer 
  | protocol inherit this class
FatherProtocol: 
  | Inherits protocol class and adds one more abstract function
  | that returns next layer protocol. All class that can have a next-layer 
  | protocol inherit this class
Protocol classes (TCPProtocol, DNSProtocol etc)
  | all protocol classes have protocol headers and a constructor 
  | that takes raw packet as parameter. Class decodes raw packet and 
  | is able to print information about itself to the logging file
PacketDecoder
  | The purpose of this class is to perform operations of decoding packet,
  | determining it's type and finding some specific field or area in it.
  | THis class is used in Protocol classes (TCPprotocol, etc) constructors
  | and may be used in other classes that needs to find data in raw
  | packet data.

 **enumerations**
ProtocolsNumber
  | Defines constants for protocols
Ipv6NextHeaderValue
  | Defines constants for additional IPv6 protocols

Components description
======================

Cross platform network layer
============================

Socket
------
**constructor**
::

 - Socket();
   Sets all fields as invalid (-1)
 - Socket(int socket_family, int socket_type);
   initiailizes socket, socket's protocol is to be chosen by system
 - Socket(int socket_family, int socket_type, int protocol);
   initiailizes socket
 - Socket(int socket_descriptor);
   initiailizes socket using it's descriptor.
 - ~Socket();

**destructor**
::

 - virtual ~Socket()
   Closes socket if it's not yet closed
 
**public functions**
::

 - int getSocketDescriptor() const;
   returns socket descriptor
 - bool IsCorrect() const;
   returns bool if socket is correct,
   false otherwise
 - bool Bind(const sockaddr* address);
   Binds socket to the address passed as argument
 - bool MakeSocketListener(int backlog);
   Sets backlog for listener socket

**private functions**   
::

 - void InitializeSocket(int socket_family, int socket_type, int protocol);
   initializes socket, used in constructors that takes these parameters
 - bool InitializeWithDescriptor(int descriptor);
   Initializes socket instance with descriptor and related to it information
   used in constructor
 - int CloseSocket();
   Closes current socket
 - int IdentifySocketFamily(int socket_descriptor) const;
   Gets socket family out of it's descriptor
 - int IdentifySocketType(int socket_descriptor) const;
   Gets socket type out of it's descriptor
 - int IdentifySocketProtocol(int socket_descriptor) const;
   Gets socket protocol out of it's descriptor

**private variables**
::

 - int descriptor_;
   Socket's descriptor
 - int socket_family_;
   Socket's family
 - int socket_type_;
   Socket's type
 - int protocol_;
   Socket's protocol

NetworkSniffer
------------------------

**constructor**
::

 - NetworkSniffer();
   Creates raw socket and performs some 
   specific platform dependant functions
   to make that socket a sniffer-socket
 
**destructor**
::

 - ~NetworkSniffer();

**public functions**
::

 - const char* GetPacket();
   Recieves a packet and returns it to
   the function caller
   
**private functions**
::

 -  void DetermineLocalIP(char** local_ip);
    Determines local IP and puts it into local_ip parameter
 -  void BindSnifferToLocalIp()
    Binds sniffer socket to local IP 
	
**private fields**
::

 - Socket* sniffer_socket_;
   This is an SOcket class object, used for sniffing
 - const int kSize_;
   size of buffer that is used for storing a recieved packet
 - char* buffer_;
   buffer that is used for storing a recieved packet
   
Main layer
==========

SnifferProccessor
-----------------
**constructor**
::

 - SnifferProcessor()
   Default constructor, initializes i/o class and filter class
   
**destructor**
::

 - ~SnifferProcessor()
   Cleans up used memory and resources
   
**public functions**
::

 - void Sniff()
   Functions that starts network sniffing
   It receives a packet and send to the decoding and logging function
 - void SetUserFileName(char* file_name)
   Takes new file name as a parameter and stores it as a class fields
   File with the following name will be used in the next sniffing
 - Filter* GetProtocolFilter();
   Geter-function that returns current filter setting incapsulated in
   a Filter object 
   
**public functions**
::

 - void Sniff()
   Functions that starts network sniffing
   It receives a packet and send to the decoding and logging function
 - void SetUserFileName(char* file_name)
   Takes new file name as a parameter and stores it as a class fields
   File with the following name will be used in the next sniffing
 - Filter* GetProtocolFilter();
   Getter-function that returns current filter setting incapsulated in
   a Filter object 
   
**private functions**
::

 - bool continue_sniffing_;
   This field is used for controling sniffer execution.
   If it is set to false sniffing will stop
 - SnifferIO* io_system_;
   This object controls everything related to logging
 - NetworkSniffer* sniffer_;
   This object incapsulates logic needed to recieve packets
 - const char* default_file_name_;
   this constant field stores the default name for logging file
 - char* user_file_name_;
   this field stores the user's file name if he/she provided one
 - Filter* protocol_filter_;
   Filter class incapsulates filter parameters
   
SnifferIO
---------

**constructor**
::

 - SnifferIO()
   
**destructor**
::

 - ~SnifferIO()
   
**public functions**
::

 - bool openFile(const char* fileName);
   opens file with the file name as in the fileName parameter
   if file already exists - overwrite it, if it doesn't - create new file
 - void LogPacket(const char* buffer_packet_, Filter* protocol_filter) const;
   Decodes buffer_packet and log it using protocol_filter settings
   
**private functions**
::

 - void LogProtocol(const Protocol* protocol_to_log) const;
   Takes protocol as a parameter and logs info about it to the logging file
   
**private fields**
::

 - ofstream* log_file_;
   file for logging   
   
Filter
------

**constructor**
::

 - Filter()
   creates all filter entries
   
**public functions**
::

 - void PrintSupportedProtocolsToConsole();
   Prints enumerated list of all supported protocols
   allowed protocols in filter are printed in green 
   otherwise - in red 
 - bool CheckIfProtocolAllowed(int protocol_id);
   if protocol is 'turned on' returns true and false otherwise
 - void FlipProtocolState(int protocol_number);
   changes protocol's status (on/off) in filter
   
**private functions**
::

 - void LogProtocol(const Protocol* protocol_to_log) const;
   Takes protocol as a parameter and logs info about it to the logging file
   
**private fields**
::

 - vector<FilterItem> filter_items_;
   Vector of FilterItem's that specifies filter entries - supported protocols
   
FilterItem (structure)
----------------------
**fields**
::

 - char* name;
   Protocol's name
 - int id;
   Protocol's id
 - bool allowed;
   if true - protocol is allowed for logging
   false - not allowed
   
ApplicationMenu
---------------
**constructor**
::

 - ApplicationMenu()
   creates all filter entries
   
**constructor**
::

 - ~ApplicationMenu()
   creates all filter entries
   
**public functions**
 - void MainMenu();
   Print to console menu menu and wait for user to
   choose correct menu item.
   
**private functions**
 - void ProcessChosenMenuItem(int choice);
   Perform some action depending on choice parameter
 - void StartMetworkSniffing();
   Menu item that start netwrok sniffing
 - void SetFilter();
   Function for working with filter. Prints filter entries
   Allows to change filter entries' state.
 - void SetLoggingFile();
   Requires user to insert file name for logging file
   Performs some checks for file correctness
 - void ClearScreen();
   Clears console screen.
   
Protocols layer:
================
Protocol
--------
**destructor**
::

 - virtual ~Protocol();
   
**public functions**
::

 - virtual void PrintHeaderInfoIntoFile(std::ofstream *file) const = 0;
   Takes a pointer to an ofstream object and writes information
   about protocol's header into file
     
FatherProtocol
-----------------
This class is inherited from the Protocol class
**public functions**
::

 - virtual ProtocolsNumber GetNextLevelProtocol() const = 0;
   Retuns upper-layer protocol
	 
	
IPv4protocol
------------
This class is inherited from the FatherProtocol class
**constructor**
::

 - virtual IPv4protocol(const char* buffer);
   takes a pointer to a received message and finds ip header in it.
   
**public functions**
::

 - virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
   Takes a pointer to an ofstream object and writes information
   about ip header into file
 - virtual ProtocolsNumber GetNextLevelProtocol() const;
   Retuns upper-layer protocol used in the current message
 - static int GetPacketCounter()
   Returns the total amount of this protocol received
   
**private field**
::

 - const IPHeader* ip_header_;
   ip header structure
 - static int recieved_packets_counter;
   The total amount of this protocol received
   
IPv6protocol
------------
This class is inherited from the FatherProtocol class
**constructor**
::

 - virtual IPprotocol(const char* buffer);
   takes a pointer to a received message and finds ip header in it.
   
**public functions**
::

 - virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
   Takes a pointer to an ofstream object and writes information
   about ip header into file
 - virtual ProtocolsNumber GetNextLevelProtocol() const;
   Retuns upper-layer protocol used in the current message
 - static int GetPacketCounter()
   Returns the total amount of this protocol received
   
**private functions**
::

 - void PrintFixedHeader(const IPv6FixedHeader* header, 
                          std::ofstream* file) const;
   Print Fixed ipv6 header information to the logging file
 - void PrintHopByHopHeader(const IPv6HopByHopHeader* header, 
                             std::ofstream* file) const;
   Print Fixed ipv6 header information to the logging file
 - void PrintDestinationHeader(const IPv6DestinationHeader* header, 
                                std::ofstream* file) const;
   Print Destination ipv6 header information to the logging file
 - void PrintRoutingHeader(const IPv6RoutingHeader* header, 
                            std::ofstream* file) const;
   Print Routing ipv6 header information to the logging file
 - void PrintFragmentHeader(const IPv6FragmentHeader* header, 
                             std::ofstream* file) const;
   Print Fragmen ipv6 header information to the logging file
   
**private field**
::

 - const char* packet_buffer_;
   A pointer to the packet buffer
 - std::vector<Ipv6NextHeaderValue> headers_;
   Sequence of IPv6's additional headers ids used in the packet
 - ProtocolsNumber next_level_protocol;
   Indicates next layer prtocol (TCP, etc)
 - static int recieved_packets_counter;
   The total amount of this protocol received
   
DNSprotocol
-----------
This class is inherited from the Protocol class
**constructor**
::

 - virtual DNSprotocol(const char* buffer);
   takes a pointer to a received message and finds dns header in it.
   
**public functions**
::

 - virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
   Takes a pointer to an ofstream object and writes information
   about dns header into file
 - static int GetPacketCounter()
   Returns the total amount of this protocol received
   
**private field**
::

 - const DNSHeader* dns_header_;
   dns header structure
 - static int recieved_packets_counter;
   The total amount of this protocol received
   
ICMPprotocol
------------
This class is inherited from the Protocol class
**constructor**
::

 - virtual ICMPprotocol(const char* buffer);
   takes a pointer to a received message and finds ICMP header in it.
   
**public functions**
::

 - virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
   Takes a pointer to an ofstream object and writes information
   about ICMP header into file
 - static int GetPacketCounter()
   Returns the total amount of this protocol received
   
**private field**
::

 - const DNSHeader* dns_header_;
   ICMP header structure
 - static int recieved_packets_counter;
   The total amount of this protocol received
   
TCPprotocol
------------
This class is inherited from the Protocol class
**constructor**
::

 - virtual TCPPprotocol(const char* buffer);
   takes a pointer to a received message and finds TCP header in it.
   
**public functions**
::

 - virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
   Takes a pointer to an ofstream object and writes information
   about TCP header into file
 - virtual ProtocolsNumber GetNextLevelProtocol() const;
   Retuns upper-layer protocol used in the current message
 - static int GetPacketCounter()
   Returns the total amount of this protocol received
   
**private field**
::

 - const TCPHeader* tcp_header_;
   TCP header structure
 - static int recieved_packets_counter;
   The total amount of this protocol received
   
UDPprotocol
-----------
This class is inherited from the Protocol class
**constructor**
::

 - virtual UDPPprotocol(const char* buffer);
   takes a pointer to a received message and finds UDP header in it.
   
**public functions**
::

 - virtual void PrintHeaderInfoIntoFile(std::ofstream* file) const;
   Takes a pointer to an ofstream object and writes information
   about UDP header into file
 - virtual ProtocolsNumber GetNextLevelProtocol() const;
   Retuns upper-layer protocol used in the current message
 - static int GetPacketCounter()
   Returns the total amount of this protocol received
   
**private field**
::

 - const UDPHeader* udp_header_;
   UDP header structure
 - static int recieved_packets_counter;
   The total amount of this protocol received

PacketDecoder
-------------   
**public functions**
::

 - void DecodeIpv6Header(const char* ipv6_header_begining,  // IN
                          std::vector<Ipv6NextHeaderValue>* ipv6_headers) const;  // OUT
   Decodes sequence of ipv6 additional headers and stroe the in the actual order
   in "ipv6_headers" vector.
 - ProtocolsNumber GetIPv6NextLayerProtocol(const char* ipv6_header_begining,  // IN
                                             char** next_layer_protocol) const;  // OUT
   Returns nex layer protocol in ipv6 packet after ipv6's last additional header
   Writes next layer protocol position to the next_layer_protocol argument
 - ProtocolsNumber GetIPv4NextLayerProtocol(const char* ipv4_header_begining,   // IN
                                             char** next_layer_protocol) const;  // OUT
   Returns next layer protocol in ip4 packet
 - const ICMPheader* FindICMPHeaderInPacket(const char* packet_buffer) const;
   Takes a pointer to ip header and returns a ICMP header 
   if there is one
 - const DNSHeader* FindDNSHeaderInPacket(const char* packet_buffer) const;
   Takes a pointer to ip header and returns a DNS header 
   if there is one
 - const TCPHeader* FindTCPHeaderInPacket(const char* packet_buffer) const;
   Takes a pointer to ip header and returns a TCP header 
   if there is one
 - const UDPHeader* FindUDPHeaderInPacket(const char* packet_buffer) const;
   Takes a pointer to ip header and returns a UDP header 
   if there is one
 - IPversion DetermineIPversion(const char* ip_header) const;
   Takes a pointer to ip header and detrmines it's version
  
enumerations
------------

**ProtocolsNumber**

  - kInvalid = -1, 
  - kTCP = 6, 
  - kUDP = 17, 
  - kIP_v4 = 4, 
  - kIP_v6 = 41, 
  - kDNS = 53, 
  - kICMP = 1
  
**Ipv6NextHeaderValue**
| IPv6 defines the following new values for the Next Header field.

 Possible values according to RFC 3542:
 
 - #define IPPROTO_HOPOPTS   0    IPv6 Hop-by-Hop options 
 - #define IPPROTO_IPV6     41    IPv6 header 
 - #define IPPROTO_ROUTING  43    IPv6 Routing header 
 - #define IPPROTO_FRAGMENT 44    IPv6 fragment header 
 - #define IPPROTO_ESP      50    encapsulating security payload 
 - #define IPPROTO_AH       51    authentication header 
 - #define IPPROTO_ICMPV6   58    ICMPv6 
 - #define IPPROTO_NONE     59    IPv6 no next header 
 - #define IPPROTO_DSTOPTS  60    IPv6 Destination options 
 
| For the sake of giving them understandable names "Ipv6Headres" enum is defined
 
  - kHopByHop = 0, 
  - kIPv6 = 41, 
  - kRoutingHeader = 43, 
  - kFragmentHeader = 44, 
  - kEncapsulatingSecurityPayload = 50,
  - kAuthentication = 51, 
  - kICMPv6 = 58, 
  - kNoNextHeader = 59, 
  - kDestinationOptins = 60