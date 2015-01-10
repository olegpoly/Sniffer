#define _CRT_SECURE_NO_WARNINGS
#include "application_menu.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <unistd.h>
#endif

#include "filter.h"

#define END_SYMBOL_LENGTH 1
#define EXIT_COMMAND "exit"

// Constructor
ApplicationMenu::ApplicationMenu() {
    sniffer_ = new SnifferProcessor();
    exit_application_ = false;
}

// Destructor
ApplicationMenu::~ApplicationMenu() {
    delete sniffer_;
}

// Print to console menu menu and wait for user to
// choose correct menu item.
void ApplicationMenu::MainMenu() {
    int choice;  // holds user's menu item choice
    
    // Wait till user choose correct menu item
    while (!exit_application_) {
        ClearScreen();
        
        printf("1) Start network sniffing\n");
        printf("2) Set filter\n");
        printf("3) Set logging file\n");
        printf("4) Exit\n");
        
        printf("Choose menu item:");
        scanf("%d", &choice);
        
        if (choice < kStartNetworkSniffing || choice > kExit) {
            printf("wrong menu item");
        } else {
            ProcessChosenMenuItem(choice);
        }
    }
}

// Prform some action depending on choice parameter
void ApplicationMenu::ProcessChosenMenuItem(int choice) {
    // Process user's choice
    switch (choice) {
      case kStartNetworkSniffing: {
        StartMetworkSniffing();
        break;
      }  // kStartNetworkSniffing
      case kSetFilter: {
        SetFilter();
        break;
      }  // kSetFilter
      case kSetLoggingFile: {
        SetLoggingFile();
        break;
      } // kSetLoggingFIle
      case kExit: {
        exit_application_ = true;
        break;
      }  // kExit
      default: {
        break;
      }  // default
    }
}

// Menu item that start netwrok sniffing
void ApplicationMenu::StartMetworkSniffing() {
    printf("Press SHIFT + S to stop sniffer\n\n");
    sniffer_->Sniff();  // starts intercepting traffic and logging
    // clear the screen
    fflush(stdout);
    ClearScreen();
}

// Function for working with filter
// Prints filter entries
// Allows to change filter entries' state
void ApplicationMenu::SetFilter() {
    Filter* protocol_filter = sniffer_->GetProtocolFilter();
    int exit_number = -1;
    
    while (true) {
        ClearScreen();
        
        // Print all supported protocols
        // Prints protocols that are 'turned on' in green
        // otherwise in red
        protocol_filter->PrintSupportedProtocolsToConsole();
        
        printf("%d) exit\n", exit_number);
        
        // Wait for user's input
        int choice;
        printf("insert protocol's id to change it's state in filter:\n");
        scanf("%d", &choice);
        
        if (choice == exit_number) {
            return;
        }
        
        // flip filter item's status - to be loggod or not
        protocol_filter->FlipProtocolState(choice);
    }
}

// Requires user to insert file name for logging file
// Performs some checks for file correctness
void ApplicationMenu::SetLoggingFile() {
    const int kFileNameMaxSize = 260;
    char users_input[kFileNameMaxSize];
    char* error_message = "";
    
    // Loop untill user insert correct file name
    // or type exit command
    do {
        ClearScreen();
        printf("%s\n", error_message);
        error_message = NULL;
        printf("insert file name (without extension)\n");
		printf("type '%s' (without paranthesis) to return\n", EXIT_COMMAND);
        printf("insert file name:");
        
        scanf("%s", users_input);
        
        // if user typed "exit" function ends 
        if (strcmp(users_input, EXIT_COMMAND) == 0) {
            return;
        }

        error_message = sniffer_->SetUserFileName(users_input);
    } while (error_message != NULL);
}

// clears console screen
void ApplicationMenu::ClearScreen() {
#ifdef _WIN32 || _WIN64
    system("cls");
#elif defined __linux__
    system("clear");
#endif
}


