/**
 * @file sqlinj.h
 * @brief Модуль для обнаружения уязвимостей SQL-инъекции
 *
 * Предоставляет функциональность для сканирования веб-приложений
 * на наличие SQL-инъекций, включая тесты error-based, boolean-based
 * и time-based.
 *
 * @author Усольцев, Ялфимов, Королев
 * @date 2025-06-13
 */
#ifndef SQLINJ_H
#define SQLINJ_H

#include <string>

/**
 * @brief Выполняет комплексное сканирование на SQL-инъекции по указанному URL.
 *
 * Для каждого параметра запроса отправляет error-based, boolean-based и
 * time-based полезные нагрузки и сообщает о потенциальных уязвимостях.
 *
 * @param urlStr URL для сканирования (включая строку запроса).
 */
void scan_sqli(const std::string& urlStr);

#endif // SQLINJ_H