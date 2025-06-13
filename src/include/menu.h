//
// Created by olegek on 6/13/25.
//

#ifndef BANNER_H
#define BANNER_H

// Печатает баннер с ASCII-арт и информацией о проекте
void print_banner();

// Печатает главное меню с баннером и опциями
void print_menu();

// Очищает вывод консоли
void clear_console();

// Печатает меню выбора типа сканирования и возвращает выбранный тип
int input_menu_option();

// Запрашивает у пользователя URL-адрес цели и возвращает его
std::string input_target_url();

#endif //BANNER_H
