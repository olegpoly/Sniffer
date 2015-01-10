//  Copyright 2014 Oleh Chernygevych

#ifdef _WIN32 || _WIN64
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Mstcpip.h>
#pragma comment (lib, "Ws2_32.lib")
#define MAX_HOST_NAME_LENGTH 16
#elif defined __linux__
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#define MAX_HOST_NAME_LENGTH 255
#define SOCKET_ERROR -1
#endif

#include "socket.h"

#include <stdio.h>

#define INCORRECT_SOCKET -1
#define INCORRECT_DOMAIN -1
#define INCORRECT_TYPE -1
#define INCORRECT_PROTOCOL -1

Socket::Socket() {
    descriptor_ = INCORRECT_SOCKET;
}

Socket::Socket(int socket_family, int socket_type) {
    InitializeSocket(socket_family, socket_type, 0);
}

Socket::Socket(int socket_family, int socket_type, int protocol) {
    InitializeSocket(socket_family, socket_type, protocol);
}

// Private function used in constructors to initialize socket
void Socket::InitializeSocket(int socket_family, int socket_type, int protocol) {
    // Creates socket
    descriptor_ = socket(socket_family, socket_type, protocol);
    
    // If function parameters are incorrect set descriptor as incorrect
    // and finish this function
    if (descriptor_ == INCORRECT_SOCKET) {
        perror("error on socket creation: ");
        return;
    } else {
        // if protocol is 0 then socket uses default protocol
        if (protocol != 0) {
            this->protocol_ = protocol;
        } else {
            // determine which protocol us set be default
            protocol_ = IdentifySocketProtocol(descriptor_);
        }
        
        this->socket_family_ = socket_family;
        this->socket_type_ = socket_type;
    }
}

int Socket::CloseSocket() const {
#ifdef _WIN32 || _WIN64
    return closesocket(descriptor_);
#elif defined __linux__
    return close(descriptor_);
#endif
}

Socket::Socket(int socket_descriptor) {
    InitializeWithDescriptor(socket_descriptor);
}

Socket::~Socket() {
    CloseSocket();
}

//int Socket::GetSocketDescriptor() const {
//    return descriptor_;
//}

// Takes socket descriptor as a parameter and determines it's domain
int Socket::IdentifySocketFamily(int socket_descriptor) const {
    int domain = INCORRECT_DOMAIN;
    
#ifdef _WIN32 || _WIN64
    WSAPROTOCOL_INFO pinf;
    int iSize = sizeof(pinf);
    getsockopt(socket_descriptor, SOL_SOCKET, SO_PROTOCOL_INFOA, 
              (char *)&pinf, &iSize);
    domain = pinf.iAddressFamily;
#elif defined __linux__
    getsockopt(socket_descriptor, SOL_SOCKET, SO_DOMAIN, &domain,
               reinterpret_cast<socklen_t*>(sizeof(domain)));
#endif
    
    return domain;
}

// Takes socket descriptor as a parameter and determines it's type
int Socket::IdentifySocketType(int socket_descriptor) const {
    int type = INCORRECT_TYPE;
    
#ifdef _WIN32 || _WIN64
    WSAPROTOCOL_INFO pinf;
    int iSize = sizeof(pinf);
    getsockopt(socket_descriptor, SOL_SOCKET, SO_PROTOCOL_INFOA, 
              (char *)&pinf, &iSize);
    type = pinf.iSocketType;
#elif defined __linux__
    getsockopt(socket_descriptor, SOL_SOCKET, SO_TYPE, &type,
               reinterpret_cast<socklen_t*>(sizeof(type)));
#endif
    
    return type;
}

// Takes socket descriptor as a parameter and determines it's protocol
int Socket::IdentifySocketProtocol(int socket_descriptor) const {
    int protocol = INCORRECT_PROTOCOL;
    
#ifdef _WIN32 || _WIN64
    WSAPROTOCOL_INFO pinf;
    int iSize = sizeof(pinf);
    getsockopt(socket_descriptor, SOL_SOCKET, SO_PROTOCOL_INFOA, 
              (char *)&pinf, &iSize);
    protocol = pinf.iProtocol;
#elif defined __linux__
    getsockopt(socket_descriptor, SOL_SOCKET, SO_PROTOCOL, &protocol,
               reinterpret_cast<socklen_t*>(sizeof(protocol)));
#endif
    
    return protocol;
}

// Initialzie socket with an existing socket
bool Socket::InitializeWithDescriptor(int descriptor) {
    if (descriptor < 0) return false;
    
    // if this object is already initialized with some socket,
    // close it
    CloseSocket();
    
    this->descriptor_ = descriptor;
    this->protocol_ = IdentifySocketProtocol(descriptor);
    this->socket_family_ = IdentifySocketFamily(descriptor);
    this->socket_type_ = IdentifySocketType(descriptor);
    
    return true;
}

bool Socket::IsCorrect() const {
    if (descriptor_ == INCORRECT_SOCKET) {
        return false;
    } else {
        return true;
    }
}

// Bind socket to an address
bool Socket::Bind(const sockaddr* address) {
    if (address == NULL) {
        return false;
    }
    
    int result = bind(descriptor_, address, sizeof(*address));
    
    if (result == 0) {
        return true;
    } else {
        return false;
    }
}

// Make socket a listner and set it's backlog
bool Socket::MakeSocketListener(int backlog) {
    if (backlog < 1) return false;
    if (descriptor_ == INCORRECT_SOCKET) return false;
    
    int result = listen(descriptor_, backlog);
    
    if (result == 0){
        return true;
    } else {
        return false;
    }
}

// Recieves a packet
bool Socket::Recieve(char** buffer, int buffer_size) {
    if (buffer == NULL) return false;
    if (*buffer == NULL) return false;
    if (buffer_size < 0) return false;

    int bytes_recieved;  // number of recieved bytes

    bytes_recieved = recv(descriptor_, *buffer, buffer_size, 0);
    if (bytes_recieved < 0) {
        return false;
    }  // if

    return true;
}

void Socket::BindSnifferToLocalIp() {
    // Convert ip to network format
    const int kLocalIpSize = 12;
    char* local_ip;
    DetermineLocalIP(&local_ip);

    struct sockaddr_in dest = { 0 };

    // local address
    //dest.sin_addr.s_addr = *(reinterpret_cast<ULONG*>(local_ip2));
    int size = sizeof(dest.sin_addr.s_addr);
    memcpy(&dest.sin_addr.s_addr, local_ip, sizeof(dest.sin_addr.s_addr));
    dest.sin_family = AF_INET;

    // bind sniffer_socket_ to the local ip
    int bind_success = bind(descriptor_,
        (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR;

    if (bind_success == SOCKET_ERROR) {
        printf("bind() failed.\n");
    }

    // Enable sniffer_socket_ to sniff
    // needed only for windows
#ifdef _WIN32 || _WIN64
    int in_buffer = 1;
    int bytes_returned;
    if (WSAIoctl(descriptor_, SIO_RCVALL, &in_buffer,
        sizeof(in_buffer), 0, 0,
        (LPDWORD)&bytes_returned, 0, 0) == SOCKET_ERROR) {
        printf("WSAIoctl() failed.\n");
        printf("%d", WSAGetLastError());
    }
#endif
}

// make socket non blocking
void Socket::MakeSocketNonBlocking() {
#ifdef __linux__
    fcntl(descriptor_, F_SETFL, O_NONBLOCK);
#elif defined _WIN32 || _WIN64
    u_long iMode = 1;
    ioctlsocket(descriptor_, FIONBIO, &iMode);
#endif
}

void Socket::DetermineLocalIP(char** local_ip) {
    // Host name can have different max length in linux and windows
    char hostname[MAX_HOST_NAME_LENGTH] = { 0 };

    //Retrive the local hostname
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        printf("gethostname error\n");
        return;
    }

    //Retrive the available IPs of the local host
    struct hostent *local_host;
    local_host = gethostbyname(hostname);
    if (local_host == NULL) {
        printf("gethostbyname error\n");
        return;
    }

    *local_ip = local_host->h_addr_list[0];
}