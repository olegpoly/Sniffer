#ifndef APPLICATION_MENU_H_
#define APPLICATION_MENU_H_

#include "sniffer_processor.h"

// Class for console interface
class ApplicationMenu {
  public:
    ApplicationMenu();
    ~ApplicationMenu();
    void MainMenu();
    
  private:
    void ProcessChosenMenuItem(int choice);
    void StartMetworkSniffing();
    void SetFilter();
    void SetLoggingFile();
    void ClearScreen();
    enum MainMenuItems { kStartNetworkSniffing = 1, kSetFilter, kSetLoggingFile, kExit };
    SnifferProcessor* sniffer_;
    bool exit_application_;
    ApplicationMenu(const ApplicationMenu&);
    void operator=(const ApplicationMenu&);
};

#endif  // APPLICATION_MENU_H_


