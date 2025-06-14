
// csrf.cpp
#include "csrf.h"

#include <boost/url.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>

#include <chrono>
#include <iostream>
#include <string>

namespace beast = boost::beast;
namespace http  = beast::http;
namespace net   = boost::asio;
namespace urls  = boost::urls;
using tcp       = net::ip::tcp;


static std::string getNoCookies(const std::string& host,
                                const std::string& target,
                                const std::string& port,
                                double&            durationSec)
{
    try {
        net::io_context ioc;
        tcp::resolver  resolver(ioc);
        beast::tcp_stream stream(ioc);
        beast::flat_buffer buffer;

        auto const results = resolver.resolve(host, port);
        stream.connect(results);

        auto start = std::chrono::high_resolution_clock::now();

        http::request<http::string_body> req{http::verb::get, target, 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, "csrf-tester/1.0");
        // Не добавляем Cookie, Referer, Origin

        http::write(stream, req);

        http::response<http::string_body> res;
        http::read(stream, buffer, res);

        durationSec = std::chrono::duration<double>(
                          std::chrono::high_resolution_clock::now() - start)
                          .count();

        return res.body();
    } catch (const std::exception& ex) {
        std::cerr << "[!] CSRF request failed: " << ex.what() << '\n';
        durationSec = 0.0;
        return {};
    }
}


std::string scan_csrf(const std::string& urlStr)
{
    auto parsed = urls::parse_uri(urlStr);
    if (!parsed)
        return "[!] Invalid URL\n";

    urls::url_view urlView = *parsed;
    std::string    host    = std::string(urlView.host());
    std::string    port    = urlView.port().empty() ? "80"
                                                    : std::string(urlView.port());

    double duration = 0.0;
    std::string body = getNoCookies(host, std::string(urlView.encoded_target()),
                                    port, duration);

    std::ostringstream oss;
    if (body.empty()) {
        oss << "[!] No response body\n";
    } else {
        oss << "[*] Response size without cookies: " << body.size() << " bytes\n";

    }
    return oss.str();
}