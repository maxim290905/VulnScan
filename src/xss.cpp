#include "xss.h"

#include <curl/curl.h>
#include <iostream>
#include <regex>
#include <sstream>

// удобные алиасы
using std::cerr;
using std::cout;
using std::string;
using std::vector;

/* ------------------------ libcurl callback ‑------------------------------ */
size_t XSSScanner::WriteCallback(void* data,
                                 size_t size,
                                 size_t nmemb,
                                 std::string* out)
{
    const size_t total = size * nmemb;
    out->append(static_cast<char*>(data), total);
    return total;
}

/* ------------------------ ctor / API ‑------------------------------------ */
XSSScanner::XSSScanner(const std::string& url) : target_url(url) {}

void XSSScanner::scan()
{
    cout << "[*] Scanning for XSS vulnerabilities on: " << target_url << '\n';
    find_forms();
    test_reflected_xss();
}

/* ------------------------ helpers ‑--------------------------------------- */
void XSSScanner::find_forms()
{
    const string html = fetch_url(target_url);
    if (html.empty()) {
        cerr << "[-] Failed to fetch page content\n";
        return;
    }

    std::regex form_re(R"(<form[^>]*action=['"]?([^'">\s]+))",
                       std::regex::icase);
    std::smatch m;
    auto         it = html.cbegin();

    while (std::regex_search(it, html.cend(), m, form_re)) {
        string action = m[1];

        // относительный → абсолютный
        if (action.rfind("http", 0) != 0) {
            if (!target_url.empty() && target_url.back() != '/'
                && action.front() != '/')
                action = target_url + '/' + action;
            else
                action = target_url + action;
        }

        cout << "[+] Found form with action: " << action << '\n';
        form_urls.emplace_back(std::move(action));
        it = m.suffix().first;
    }
}

void XSSScanner::test_reflected_xss()
{
    static const vector<string> payloads = {
        R"(<script>alert(1)</script>)",
        R"("><script>alert(1)</script>)",
        R"(javascript:alert(1))",
        R"(onload=alert(1))",
        R"(src=javascript:alert(1))"};

    for (const string& form : form_urls) {
        cout << "[*] Testing form at: " << form << '\n';
        CURL* curl = curl_easy_init();

        for (const string& p : payloads) {
            char* enc = curl_easy_escape(curl, p.c_str(),
                                         static_cast<int>(p.length()));

            std::ostringstream oss;
            oss << form << "?test=" << enc;
            const string test_url = oss.str();
            curl_free(enc);

            const string resp = fetch_url(test_url);
            if (resp.find(p) != string::npos) {
                cout << "[-] POSSIBLE XSS VULNERABILITY DETECTED!\n"
                     << "    Payload: " << p << '\n'
                     << "    URL:     " << test_url << "\n\n";
            }
        }
        curl_easy_cleanup(curl);
    }
}

std::string XSSScanner::fetch_url(const std::string& url)
{
    string response;
    CURL*  curl = curl_easy_init();
    if (!curl) return response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "vuln_scan/1.0");

    if (auto rc = curl_easy_perform(curl); rc != CURLE_OK)
        cerr << "[-] Error fetching " << url << ": "
             << curl_easy_strerror(rc) << '\n';

    curl_easy_cleanup(curl);
    return response;
}