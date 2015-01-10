#include "filter.h"
#include "protocol.h"

#ifdef _WIN32 || _WIN64
#include <Windows.h>
#include <Wincon.h>
#elif defined __linux__
#include <netinet/in.h>
#endif

#define ITEM_ALLOWED 1
#define ITEM_NOT_ALLOWED 0

#define STANDART_CONSOLE_COLOR 7

// Constructor
Filter::Filter() {
    // Add filters to vector
    filter_items_.push_back({ "IPv4", kIP_v4, ITEM_ALLOWED });
    filter_items_.push_back({ "IPv6", kIP_v6, ITEM_ALLOWED });
    filter_items_.push_back({ "TCP", kTCP, ITEM_ALLOWED });
    filter_items_.push_back({ "UDP", kUDP, ITEM_ALLOWED });
    filter_items_.push_back({ "DNS", kDNS, ITEM_ALLOWED });
    filter_items_.push_back({ "ICMP", kICMP, ITEM_ALLOWED });
}

// Prints enumerated list of all supported protocols
// allowed protocols in filter are printed in green
// otherwise - in red
void Filter::PrintSupportedProtocolsToConsole()  {
    std::vector<FilterItem>::iterator filter_items_iterator = filter_items_.begin();

#ifdef _WIN32 || _WIN62
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);

    do {
        if (filter_items_iterator->allowed == true) {
            SetConsoleTextAttribute(console, FOREGROUND_GREEN);
        } else {
            SetConsoleTextAttribute(console, FOREGROUND_RED);
        }

        printf("%d: %s\n", filter_items_iterator->id, filter_items_iterator->name);
        filter_items_iterator++;
    } while (filter_items_iterator != filter_items_.end());

    SetConsoleTextAttribute(console, STANDART_CONSOLE_COLOR);  // return to normal console text colour
#elif defined __linux__
    do {
        if (filter_items_iterator->allowed == true) {
            printf("\033[1;32m%d: %s \n", filter_items_iterator->id, 
                                          filter_items_iterator->name);
        } else {
            printf("\033[1;31m%d: %s \n", filter_items_iterator->id, 
                                          filter_items_iterator->name);
        }

        filter_items_iterator++;
    } while (filter_items_iterator != filter_items_.end());
    printf("\033[0m");
#endif
}

// if protocol is 'turned on' returns true and false otherwise
bool Filter::CheckIfProtocolAllowed(int protocol_id) {
    std::vector<FilterItem>::iterator filter_items_iterator = filter_items_.begin();

    while (filter_items_iterator != filter_items_.end()) {
        if (filter_items_iterator->id == protocol_id) {
            return filter_items_iterator->allowed;
        }

        filter_items_iterator++;
    }
}

// changes protocol's status (on/off) in filter
void Filter::FlipProtocolState(int protocol_id) {
    std::vector<FilterItem>::iterator filter_items_iterator = filter_items_.begin();

    while (filter_items_iterator != filter_items_.end()) {
        if (filter_items_iterator->id == protocol_id) {
            filter_items_iterator->allowed = !filter_items_iterator->allowed;
            break;
        }

        filter_items_iterator++;
    }
}


