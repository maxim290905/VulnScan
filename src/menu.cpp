
#include "include/menu.h"
#include "pch.h"

// Очищает экран консоли (с помощью полной перезагрузки терминала)
void clear_console() {
    std::cout << "\033c" << std::flush;
}

// Печатает баннер с ASCII-арт и информацией о проекте
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

// Печатает главное меню с баннером и опциями
void print_menu() {
    clear_console();
    print_banner();

}

std::string input_target_url() {
    std::string url;
    static const char* inform = R"(
Welcome to VulnScan!
Enter URL: )";
    std::cout << inform;
    std::cin >> url;
    if (url.empty()) {
        std::cerr << "Error: URL cannot be empty." << std::endl;
        return input_target_url(); // Prompt again if the URL is empty
    }
    if (url.find("http://") != 0 && url.find("https://") != 0) {
        std::cerr << "Error: URL must start with 'http://' or 'https://'." << std::endl;
        return input_target_url(); // Prompt again if the URL is invalid
    }
    print_banner();
    return url;
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
    if (std::cin.fail() || !(option >= 0 && option <= 4 || option == 9)) {
        std::cin.clear(); // Clear the error flag
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
        print_banner();
        std::cerr << "Invalid option. Please try again." << std::endl;

        return input_menu_option(); // Prompt again for a valid option
    }
    print_banner();
    return option;
}
