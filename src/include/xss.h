#ifndef XSS_H
#define XSS_H

#include <string>
#include <vector>

class XSSScanner {
public:
    explicit XSSScanner(const std::string& url);
    void scan();

private:
    std::string target_url;
    std::vector<std::string> form_urls;

    void find_forms();
    void test_reflected_xss();
    std::string fetch_url(const std::string& url);

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output);
};

#endif // XSS_H
