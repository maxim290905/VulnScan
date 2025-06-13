
#include "include/menu.h"
#include "pch.h"

// Очищает экран консоли (с помощью полной перезагрузки терминала)
void clear_console() {
    std::cout << "\033c" << std::flush;
}

// Печатает баннер с ASCII-арт и информацией о проекте
void print_banner() {
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
    return url;
}

int input_menu_option() {
    int option;
    std::cout << "Select an option:\n";
    std::cout << "1. Scan for XSS vulnerabilities\n";
    std::cout << "2. Scan for CSRF vulnerabilities\n";
    std::cout << "3. Scan for SQL Injection vulnerabilities\n";
    std::cout << "4. Upload a file\n";
    std::cout << "5. Exit\n";
    std::cout << "Enter your choice: ";
    std::cin >> option;
    return option;
}
