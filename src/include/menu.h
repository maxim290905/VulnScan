

#ifndef BANNER_H
#define BANNER_H

// Очищает консоль и печатает баннер с ASCII-арт и информацией о проекте
void print_banner();

// Запрашивает у пользователя URL-адрес цели и возвращает его
void change_url(std::string& url);

// Очищает вывод консоли
void clear_console();

// Печатает меню выбора типа сканирования и возвращает выбранный тип
int input_menu_option();

// Обрабатывает выбранный пользователем пункт меню
void handle_option(std::string& url);

// Обрабатывает неизвестный пункт меню и возвращает вызов input_menu_option
int unknown_option_handler(int option);

// Запрашивает у пользователя URL-адрес цели и возвращает его
std::string input_target_url();

#endif //BANNER_H
