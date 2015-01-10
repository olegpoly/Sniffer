#ifndef FILTER_H_
#define FILTER_H_

#include "protocol.h"

#include <vector>

// Used in Filter to store inforamation
// about protocol and it's state(on/off)
struct FilterItem {
    char* name;
    int id;
    bool allowed;
};

// stores inforamation
// about protocol and it's state(on/off)
class Filter {
  public:
    Filter();
    void PrintSupportedProtocolsToConsole();
    bool CheckIfProtocolAllowed(int protocol_id);
    void FlipProtocolState(int protocol_number);

  private:
    std::vector<FilterItem> filter_items_;
    Filter(const Filter&);
    void operator=(const Filter&);
};

#endif  // FILTER_H_


