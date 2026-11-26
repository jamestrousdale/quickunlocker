#include "http.h"

#include <charconv>
#include <chrono>
#include <memory>
#include <stdexcept>

namespace quickunlock {
namespace {

void Require(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

struct CloseInternet {
    void operator()(void* handle) const noexcept { WinHttpCloseHandle(handle); }
};
using InternetHandle = std::unique_ptr<void, CloseInternet>;

}

std::wstring ToWide(std::string_view text) {
    if (text.empty()) return {};
    const auto input = static_cast<int>(text.size());
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), input, nullptr, 0);
    Require(size > 0, "Invalid UTF-8.");
    std::wstring result(size, L'\0');
    Require(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), input, result.data(), size) == size,
            "Could not convert UTF-8.");
    return result;
}

std::string ToUtf8(std::wstring_view text) {
    if (text.empty()) return {};
    const auto input = static_cast<int>(text.size());
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), input, nullptr, 0, nullptr, nullptr);
    Require(size > 0, "Invalid UTF-16.");
    std::string result(size, '\0');
    Require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), input,
                                result.data(), size, nullptr, nullptr) == size, "Could not convert UTF-16.");
    return result;
}

bool IsCapability(std::string_view text) noexcept {
    return text.size() >= 16 && text.size() <= 64 &&
        text.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == text.npos;
}

HttpClient::HttpClient(std::string_view origin) {
    constexpr std::string_view scheme = "https://";
    Require(origin.starts_with(scheme) && origin.size() <= 268, "Expected an HTTPS origin.");
    const auto authority = origin.substr(scheme.size());
    const auto separator = authority.find(':');
    host_ = authority.substr(0, separator);
    Require(!host_.empty() &&
            host_.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-.") == host_.npos &&
            host_.front() != '.' && host_.back() != '.', "Expected a lowercase HTTPS hostname.");

    unsigned port = INTERNET_DEFAULT_HTTPS_PORT;
    if (separator != authority.npos) {
        const auto text = authority.substr(separator + 1);
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
        Require(error == std::errc{} && end == text.data() + text.size() && port > 0 && port <= 65535 &&
                port != INTERNET_DEFAULT_HTTPS_PORT && std::to_string(port) == text, "Invalid HTTPS port.");
    }

    InternetHandle session(WinHttpOpen(L"quickunlocker/1", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    Require(static_cast<bool>(session), "Could not initialize WinHTTP.");
    InternetHandle connection(WinHttpConnect(session.get(), ToWide(host_).c_str(),
                                            static_cast<INTERNET_PORT>(port), 0));
    Require(static_cast<bool>(connection), "Could not initialize relay connection.");
    session_ = session.release();
    connection_ = connection.release();
}

HttpClient::~HttpClient() {
    WinHttpCloseHandle(connection_);
    WinHttpCloseHandle(session_);
}

Json HttpClient::Send(LPCWSTR method, std::string_view path, std::string body, int receiveTimeout) const {
    Require(path.starts_with("/api/") && path.size() < 256, "Invalid relay API path.");
    InternetHandle request(WinHttpOpenRequest(connection_, method, ToWide(path).c_str(), nullptr,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             WINHTTP_FLAG_SECURE));
    Require(static_cast<bool>(request), "Could not open relay request.");
    DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    Require(WinHttpSetOption(request.get(), WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)) &&
            WinHttpSetTimeouts(request.get(), 5000, 5000, 5000, receiveTimeout),
            "Could not configure relay request.");

    const auto bodyLength = static_cast<DWORD>(body.size());
    const LPCWSTR headers = body.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : L"Content-Type: application/json";
    Require(WinHttpSendRequest(request.get(), headers, body.empty() ? 0 : static_cast<DWORD>(-1),
                               body.empty() ? WINHTTP_NO_REQUEST_DATA : body.data(),
                               bodyLength, bodyLength, 0) && WinHttpReceiveResponse(request.get(), nullptr),
            "Could not read the relay response.");

    DWORD status = 0, length = sizeof(status);
    Require(WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &status, &length, WINHTTP_NO_HEADER_INDEX),
            "Could not read relay status.");
    if (status < 200 || status >= 300) {
        throw std::runtime_error("Relay returned HTTP " + std::to_string(status) + ".");
    }

    const auto readDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    std::string response;
    char buffer[4096];
    for (;;) {
        Require(std::chrono::steady_clock::now() < readDeadline, "Relay body timed out.");
        DWORD read = 0;
        Require(WinHttpReadData(request.get(), buffer, sizeof(buffer), &read), "Cannot read relay body.");
        if (!read) break;
        Require(response.size() + read <= 65536, "Relay body is too large.");
        response.append(buffer, read);
    }
    return ParseJson(response);
}

Json HttpClient::Get(std::string_view path, int receiveTimeout) const {
    return Send(L"GET", path, {}, receiveTimeout);
}

Json HttpClient::Post(std::string_view path, const Json& body) const {
    return Send(L"POST", path, body.dump(), 10000);
}

}
