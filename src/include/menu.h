/**
 * @file menu.h
 * @brief Пользовательский интерфейс и обработка меню VulnScan
 *
 * Содержит функции отображения ASCII-баннера, запроса URL и
 * пунктов меню, а также маршрутизации выбранных действий.
 *
 * @author Усольцев, Ялфимов, Королев
 * @date 2025-06-13
 */
#ifndef MENU_H
#define MENU_H

#include <string>

/** Очищает консоль с помощью ANSI-последовательностей. */
void clear_console();

/** Печатает ASCII-баннер с информацией о программе. */
void print_banner();

/**
 * @brief Запрашивает у пользователя целевой URL и выполняет базовую проверку.
 * @return Валидный URL-адрес.
 */
std::string input_target_url();

/**
 * @brief Запрашивает у пользователя выбор пункта меню и проверяет ввод.
 * @return Выбранный пункт меню.
 */
int input_menu_option();

/**
 * @brief Обрабатывает неверные пункты меню, повторно запрашивая ввод.
 * @param option Введённый пользователем пункт.
 * @return Корректный пункт меню.
 */
int unknown_option_handler(int option);

/**
 * @brief Изменяет текущий целевой URL, повторно запрашивая его у пользователя.
 * @param url Ссылка на текущую строку URL.
 */
void change_url(std::string& url);

/**
 * @brief Выполняет действие, соответствующее выбранному пункту меню.
 * @param url Ссылка на текущий URL.
 */
void handle_option(std::string& url);

#endif // MENU_H