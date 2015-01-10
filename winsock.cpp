//  Copyright 2014 Oleh Chernygevych

#ifdef _WIN32 || _WIN64
#include <WinSock2.h>

// This class initializes libraries needed for windows
// in constructor and deinitialize in destructor
// With this class user doesn't have to remember
// about WSA startup and cleanup functions

class Initialize_winsock {
  public:
    Initialize_winsock() {
        WSAData wsa_data;
        WSAStartup(WINSOCK_VERSION, &wsa_data);
    }
    ~Initialize_winsock() {
        WSACleanup();
    }
} Initialize_winsock_instance;

#endif


