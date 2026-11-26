#pragma once

#include <windows.h>
#include <winhttp.h>
#include "webauthn.h"

namespace quickunlock {

std::wstring ToWide(std::string_view text);
std::string ToUtf8(std::wstring_view text);
bool IsCapability(std::string_view text) noexcept;

class HttpClient {
public:
    explicit HttpClient(std::string_view origin);
    ~HttpClient();
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    Json Get(std::string_view path, int receiveTimeout = 10000) const;
    Json Post(std::string_view path, const Json& body) const;
    const std::string& Host() const noexcept { return host_; }

private:
    Json Send(LPCWSTR method, std::string_view path, std::string body, int receiveTimeout) const;
    std::string host_;
    HINTERNET session_ = nullptr;
    HINTERNET connection_ = nullptr;
};

}
