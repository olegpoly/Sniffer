//  Copyright 2014 Oleh Chernygevych

#ifndef SOCKET_H_
#define SOCKET_H_

#ifdef _WIN32 || _WIN64
#include <WS2tcpip.h>
#elif defined __linux__
#include <netinet/in.h>
#endif

// Class for socket descriptor
// and functions that manipulates it
class Socket {
  public:
    Socket();
    Socket(int socket_family, int socket_type);
    Socket(int socket_family, int socket_type, int protocol);
    Socket(int socket_descriptor);
    ~Socket();
    bool IsCorrect() const;
    bool Bind(const sockaddr* address);
    bool MakeSocketListener(int backlog);
    bool Recieve(char** buffer, int buffer_size);
    void BindSnifferToLocalIp();
    void MakeSocketNonBlocking();
    void DetermineLocalIP(char** local_ip);

  private:
    void InitializeSocket(int socket_family, int socket_type, int protocol);
    bool InitializeWithDescriptor(int descriptor);
    int CloseSocket() const;
    int IdentifySocketFamily(int socket_descriptor) const;
    int IdentifySocketType(int socket_descriptor) const;
    int IdentifySocketProtocol(int socket_descriptor) const;
    int descriptor_;
    int socket_family_;
    int socket_type_;
    int protocol_;
    Socket(const Socket&);
    void operator=(const Socket&);
};

#endif


