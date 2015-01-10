#define _CRT_SECURE_NO_WARNINGS
//  Copyright 2014 Oleh Chernygevych

#include "sniffer_processor.h"

#ifdef __linux__
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <termios.h>
#include <pthread.h>
#elif defined _WIN32 || _WIN64  // __linux__
#include <thread>
#include <conio.h>
#endif  // _WIN32 || _WIN64

#include <string.h>

#include "sniffer_io.h"
#include "socket.h"
#include "protocol.h"
#include "father_protocol.h"
class Protocol;
class TCPprotocol;

#define END_SYMBOL_LENGTH 1

SnifferProcessor::SnifferProcessor() : default_file_name_("log.txt") {
    io_system_ = new SnifferIO();
    protocol_filter_ = new Filter();
    continue_sniffing_ = true;
    sniffer_ = NULL;
    user_file_name_ = NULL;
}

SnifferProcessor::~SnifferProcessor() {
    delete io_system_;
    delete protocol_filter_;

    if (user_file_name_ != NULL) {
        delete user_file_name_;
    }
}

// File name for logging, provided by user
char* SnifferProcessor::SetUserFileName(const char* file_name) {
    if (file_name == NULL) return "empty file name";

    const int kFileNameMaxSize = 260;
    int file_extension_length = strlen(".txt") + END_SYMBOL_LENGTH;
    int max_file_name_length = kFileNameMaxSize - file_extension_length;

    if (strlen(file_name) > max_file_name_length) {
        return "wrong file length";
    }
    if (strpbrk(file_name, "<>:\"/\\|?*") != NULL) {
        return "wrong file name, following characters are prohibited: <>:\"/\\|?*";
    }
    if (strstr(file_name, ".txt") != NULL) {
        return "insert file name without an extension";
    }

    // Delete previous file if there is one
    // Checks are done after this operation,
    // if any of checks fail, deleted file
    // will state an error and user will not
    // be able to write to the logging file
    if (user_file_name_ != NULL) {
        delete user_file_name_;
        user_file_name_ = NULL;
    }

    // Store new file name in the "user_file_name_"
    // field
    int length = strlen(file_name);
    user_file_name_ = new char[length + END_SYMBOL_LENGTH];
    strcpy(user_file_name_, file_name);

    return NULL;
}

// Starts network sniffing
void SnifferProcessor::Sniff() {
    // Print starting message to the console
    PrintProtocolCounters();
    printf("\r");
    fflush(stdout);
    // Start thread that waits for stop-character
#ifdef _WIN32 || _WIN64
    std::thread stop_sniffer_thread(&SnifferProcessor::StopSniffer, this);
#elif defined __linux__
    pthread_t stop_sniffer_thread;
    pthread_create(&stop_sniffer_thread, NULL, 
                   &SnifferProcessor::StopSniffer, 
                   &continue_sniffing_);
#endif

    // Open file for logging information about packets
    bool open_file_result = false;

    if (user_file_name_ != NULL) {
        open_file_result = io_system_->openFile(user_file_name_);
    } else {
        open_file_result = io_system_->openFile(default_file_name_);
    }

    if (open_file_result == false) {
        printf("file opening error");
        return;
    }

    // Start network sniffing
    const char* buffer_packet_;
    sniffer_ = new NetworkSniffer();

    continue_sniffing_ = true;
    while (continue_sniffing_) {
        // Receive packet
        buffer_packet_ = sniffer_->GetPacket();

        if (buffer_packet_ != NULL) {
            io_system_->LogPacket(buffer_packet_, protocol_filter_);  // Decode packet and log it's info
            PrintProtocolCounters();
            printf("\r");
        }
    }  // while

#ifdef _WIN32 || _WIN64
    stop_sniffer_thread.join();
#endif

    delete sniffer_;
}

Filter* SnifferProcessor::GetProtocolFilter() {
    return protocol_filter_;
}

#ifdef __linux__
// Waits for shift+S keyboard combination to stop sniffer
void* SnifferProcessor::StopSniffer(void* continue_sniffing) {
    // make terminal input non-blocking
    struct termios oldSettings, newSettings;
    tcgetattr(fileno(stdin), &oldSettings);
    newSettings = oldSettings;
    newSettings.c_lflag &= (~ICANON & ~ECHO);
    tcsetattr(fileno(stdin), TCSANOW, &newSettings);

    char needed_input = 'S';
    char input;

    while (true) {
        read(fileno(stdin), &input, 1);

        if (input == needed_input) {
            (*(bool*)(continue_sniffing)) = false;
            break;
        }
    }

    // return to the previouse terminal settings
    tcsetattr(fileno(stdin), TCSANOW, &oldSettings);
}
#elif defined _WIN32 || _WIN64
// Waits for shift+S keyboard combination to stop sniffer
void SnifferProcessor::StopSniffer() {
    char needed_input = 'S';
    char input;

    while (true) {
        input = _getch();

        if (input == needed_input) {
            continue_sniffing_ = false;
            break;
        }
    }
}
#endif

// Print protocol counters
void SnifferProcessor::PrintProtocolCounters() const {
    printf("%s: %d ", "TCP", TCPprotocol::GetPacketCounter());
    printf("%s: %d ", "UDP", UDPprotocol::GetPacketCounter());
    printf("%s: %d ", "IPv4", IPv4protocol::GetPacketCounter());
    printf("%s: %d ", "IPv6", IPv6protocol::GetPacketCounter());
    printf("%s: %d ", "DNS", DNSprotocol::GetPacketCounter());
    printf("%s: %d ", "ICMP", ICMPprotocol::GetPacketCounter());
}

