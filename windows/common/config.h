#pragma once
#if !defined(_M_X64) && !defined(__x86_64__)
#error Quickunlocker requires Windows x64.
#endif
#include "webauthn.h"

#include <windows.h>
#include <filesystem>
#include <optional>

namespace quickunlock {

inline constexpr GUID ProviderId{0xfa7fbc30, 0x8d11, 0x429d, {0xb1, 0x09, 0x2e, 0xe8, 0xb9, 0xed, 0x0d, 0x71}};
inline constexpr wchar_t ProviderIdText[] = L"{FA7FBC30-8D11-429D-B109-2EE8B9ED0D71}";

struct Config {
    std::string origin;
    std::string rpId;
    std::string pcName;
    std::wstring domain;
    std::wstring username;
    std::wstring sid;
    Pins pins;
    bool operator==(const Config&) const = default;
};

class Password {
public:
    Password() = default;
    ~Password() { SecureZeroMemory(value, sizeof(value)); }
    Password(const Password&) = delete;
    Password& operator=(const Password&) = delete;

    wchar_t value[512]{};
};

std::optional<Config> LoadConfig();
void SaveConfig(const Config& config);
void StorePassword(std::wstring_view sid, const Password& password);
void LoadPassword(std::wstring_view sid, Password& password);
void DeletePassword(std::wstring_view sid);
void RegisterProvider(const std::filesystem::path& dll);
void UnregisterProvider();

}
