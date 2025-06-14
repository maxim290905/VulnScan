/**
 * @file csrf.h
 * @brief Модуль для обнаружения уязвимостей CSRF
 *
 * Предоставляет функциональность для сканирования веб-приложений
 * на предмет Cross-Site Request Forgery (CSRF). Включает методы
 * проверки защиты CSRF путём отправки запросов без cookies, Referer
 * и Origin-заголовков.
 *
 * @author Усольцев, Ялфимов, Королев
 * @date 2025-06-13
 */
#ifndef CSRF_H
#define CSRF_H

#include <string>

/**
 * @brief Сканирует указанный URL на наличие уязвимостей CSRF.
 *
 * Отправляет запрос без cookies, Referer и Origin-заголовков
 * и анализирует полученный ответ.
 *
 * @param url URL для сканирования.
 * @return Текстовый отчёт о результатах сканирования.
 */
std::string scan_csrf(const std::string& url);

#endif // CSRF_H