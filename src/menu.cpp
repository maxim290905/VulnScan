
#include "include/menu.h"
#include "pch.h"


void clear_console() {
    std::cout << "\033c" << std::flush;
}


void print_banner() {
    clear_console();
    static const char* banner = R"(
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  @n                                                           @@
@@                                                               @
@                                        @                        @
@     @@@@@@       @@@@              @@@@@@                         @
@      @@@@@       @@@                 @@@@                         @
@       @@@@@     @@@                  @@@@                         @
@       @@@@@     @@@ nnnnn   nnnnn    @@@@     @@@  @@@@           @
@        @@@@n   n@@   @@@@n   @@@@    @@@@   @@@@@@@@@@@@          @
@        @@@@@   @@@   @@@@n   @@@@    @@@@   t@@@@   @@@@@         @
@         @@@@   @@    @@@@n   @@@@    @@@@    @@@@    @@@@         @
@         @@@@@ @@@    @@@@n   @@@@    @@@@    @@@@    @@@@         @
@          @@@@ @@     @@@@n   @@@@    @@@@    @@@@    @@@@         @
@          @@@@@@@     @@@@6   @@@@    @@@@    @@@@    @@@@         @
@           @@@@@      @@@@@   @@@@    @@@@    @@@@    @@@@         @
@           @@@@@       @@@@@@@n@@@@   @@@@   @@@@@   @@@@@         @
@                         n@n                                       @
@            @@@@   @                                               @
@         @@@@@@@@@@@                                               @
@        @@@@      @@                                               @
@        @@@@       @        @          nn           @   6@         @
@        @@@@@           @@@@@@@@@   @@@@@@@@    @@@@@n@@@@@@       @
@        @@@@@@@@       @@@@    @@  @@    @@@@    @@@@n  @@@@@      @
@          @@@@@@@@n   @@@@      @        @@@@    @@@@    @@@@      @
@            n@@@@@@@  @@@@             @@@@@@    @@@@    @@@@      @
@               @@@@@@ @@@@         @@@@  @@@@    @@@@    @@@@      @
@        @       @@@@@ @@@@@       @@@@   @@@@    @@@@    @@@@      @
@        @@      @@@@@  @@@@      n@@@@   @@@@    @@@@    @@@@      @
@        @@@@n  @@@@@   @@@@@@@@@@ @@@@@@@@@@@    @@@@    @@@@      @
@        @@@@@@@@@@       @@@@@@    @@@@@ n@@@@@ @@@@@@  @@@@@@     @
@                                                                   @
 @                                                                 @
  n@                                                           @
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@t


   [---]        The Vulnerability Scanner (VulnScan)         [---]
[---]        Created by: Usoltsev, Yalfimov and Korolev         [---]
                           Version: 1.0.0
     [---] Visit: https://github.com/maxim290905/VulnScan [---]
                    [---] Telegram: @pvppve [---]

)";
    std::cout << banner;
}


std::string input_target_url() {
    print_banner();
    std::string url;
    static const char* inform = R"(
Welcome to VulnScan!
Enter URL: )";
    std::cout << inform;
    std::cin >> url;
    print_banner();
    if (url.empty()) {
        std::cerr << "Error: URL cannot be empty." << std::endl;
        return input_target_url(); // Prompt again if the URL is empty
    }
    if (url.find("http://") != 0 && url.find("https://") != 0) {
        std::cerr << "Error: URL must start with 'http://' or 'https://'." << std::endl;
        return input_target_url(); // Prompt again if the URL is invalid
    }
    return url;
}


int unknown_option_handler(int option) {
    if (std::cin.fail() || !(option >= 0 && option <= 4 || option == 9)) {
        std::cin.clear(); // Clear the error flag
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
        print_banner();
        std::cerr << "Invalid option. Please try again." << std::endl;
        return input_menu_option(); // Prompt again for a valid option
    }
    return option;
}


int input_menu_option() {
    int option;
    std::cout << "Select an option:\n";
    std::cout << "1. Scan for XSS vulnerabilities\n";
    std::cout << "2. Scan for CSRF vulnerabilities\n";
    std::cout << "3. Scan for SQL Injection vulnerabilities\n";
    std::cout << "4. Upload a file\n\n";
    std::cout << "9. Change URL\n";
    std::cout << "0. Exit\n";
    std::cout << "Enter your choice: ";
    std::cin >> option;
    print_banner();
    option = unknown_option_handler(option); // Check for invalid input
    return option;
}


void change_url(std::string& url) {
    url = input_target_url();
    }


void handle_option(std::string& url)
{
    int option = input_menu_option();
    switch (option)
    {
        // case 1: scan_xss(url);         break;
        // case 2: scan_csrf(url);        break;
        case 3: scan_sqli(url);        break;
        case 4: upload_file(url);      break;
        case 9: change_url(url);             break;
        case 0: std::cout << "Thanks for using VulnScan! Goodbye!\n"; return;
        default: break;
    }
    handle_option(url); // Recursive call to handle the next option
}