#include "config.h"
#include "http.h"

#include <ntsecapi.h>
#include <cstring>
#include <stdexcept>

namespace quickunlock {
namespace {

constexpr wchar_t ConfigKey[] = L"SOFTWARE\\quickunlocker";
constexpr wchar_t ConfigValue[] = L"Configuration";

void Check(LSTATUS status) {
    if (status != ERROR_SUCCESS) throw std::runtime_error("Registry operation failed: " + std::to_string(status));
}

class RegistryKey {
public:
    explicit RegistryKey(const wchar_t* path) {
        Check(RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, nullptr, 0,
                              KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key_, nullptr));
    }
    ~RegistryKey() { RegCloseKey(key_); }
    RegistryKey(const RegistryKey&) = delete;
    RegistryKey& operator=(const RegistryKey&) = delete;

    void Set(const wchar_t* name, const std::wstring& value) const {
        const auto size = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
        Check(RegSetValueExW(key_, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()), size));
    }

private:
    HKEY key_ = nullptr;
};

class Policy {
public:
    explicit Policy(ACCESS_MASK access) {
        LSA_OBJECT_ATTRIBUTES attributes{};
        attributes.Length = sizeof(attributes);
        CheckStatus(LsaOpenPolicy(nullptr, &attributes, access, &handle));
    }
    ~Policy() { LsaClose(handle); }
    Policy(const Policy&) = delete;
    Policy& operator=(const Policy&) = delete;

    static void CheckStatus(NTSTATUS status) {
        if (status) throw std::runtime_error("LSA operation failed: " + std::to_string(LsaNtStatusToWinError(status)));
    }

    LSA_HANDLE handle = nullptr;
};

LSA_UNICODE_STRING LsaString(std::wstring_view text) {
    const auto length = static_cast<USHORT>(text.size() * sizeof(wchar_t));
    return {length, length, const_cast<PWSTR>(text.data())};
}

std::wstring SecretName(std::wstring_view sid) {
    if (sid.size() < 5 || sid.size() > 184 || !sid.starts_with(L"S-1-") ||
        sid.substr(4).find_first_not_of(L"0123456789-") != sid.npos) {
        throw std::runtime_error("Invalid account SID.");
    }
    return L"L$quickunlocker-" + std::wstring(sid);
}

std::wstring ProviderKey() {
    return std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\")
        + ProviderIdText;
}

std::wstring ClassKey() {
    return std::wstring(L"SOFTWARE\\Classes\\CLSID\\") + ProviderIdText;
}

void RemoveKey(const std::wstring& path) {
    const auto status = RegDeleteKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), KEY_WOW64_64KEY, 0);
    if (status != ERROR_FILE_NOT_FOUND) Check(status);
}

}

std::optional<Config> LoadConfig() {
    constexpr DWORD flags = RRF_RT_REG_SZ;
    DWORD size = 0;
    const auto status = RegGetValueW(HKEY_LOCAL_MACHINE, ConfigKey, ConfigValue, flags, nullptr, nullptr, &size);
    if (status == ERROR_FILE_NOT_FOUND) return std::nullopt;
    Check(status);
    if (size < sizeof(wchar_t) || size > 65536 || size % sizeof(wchar_t)) {
        throw std::runtime_error("Invalid configuration length.");
    }
    std::wstring text(size / sizeof(wchar_t), L'\0');
    Check(RegGetValueW(HKEY_LOCAL_MACHINE, ConfigKey, ConfigValue, flags, nullptr, text.data(), &size));
    text.resize(size / sizeof(wchar_t) - 1);
    const auto data = ParseJson(ToUtf8(text));
    Config result;
    result.origin = data.at("origin").get<std::string>();
    result.rpId = data.at("rp_id").get<std::string>();
    result.pcName = data.at("pc_name").get<std::string>();
    result.sid = ToWide(data.at("sid").get<std::string>());
    result.domain = ToWide(data.at("domain").get<std::string>());
    result.username = ToWide(data.at("username").get<std::string>());
    (void)SecretName(result.sid);
    const auto& pins = data.at("pins");
    if (!pins.is_object() || pins.size() > 32 || result.username.empty() ||
        result.username.size() > 256 || result.domain.size() > 256 ||
        result.username.find(L'\0') != result.username.npos || result.domain.find(L'\0') != result.domain.npos) {
        throw std::runtime_error("Invalid sign-in configuration.");
    }
    for (const auto& [id, value] : pins.items()) {
        (void)DecodeBase64Url(id);
        const auto pin = DecodeBase64Url(value.get<std::string>());
        if (!IsP256Key(pin)) throw std::runtime_error("Invalid pinned public key.");
        result.pins.emplace(id, pin);
    }
    return result;
}

void SaveConfig(const Config& config) {
    Json pins = Json::object();
    for (const auto& [id, pin] : config.pins) pins[id] = EncodeBase64Url(pin);
    const Json data = {{"origin", config.origin}, {"rp_id", config.rpId}, {"pc_name", config.pcName},
                       {"domain", ToUtf8(config.domain)}, {"username", ToUtf8(config.username)},
                       {"sid", ToUtf8(config.sid)}, {"pins", std::move(pins)}};
    RegistryKey(ConfigKey).Set(ConfigValue, ToWide(data.dump()));
}

void StorePassword(std::wstring_view sid, const Password& password) {
    const auto name = SecretName(sid);
    auto key = LsaString(name);
    auto value = LsaString(password.value);
    const Policy policy(POLICY_CREATE_SECRET);
    Policy::CheckStatus(LsaStorePrivateData(policy.handle, &key, &value));
}

void LoadPassword(std::wstring_view sid, Password& password) {
    const auto name = SecretName(sid);
    auto key = LsaString(name);
    const Policy policy(POLICY_GET_PRIVATE_INFORMATION);
    PLSA_UNICODE_STRING value = nullptr;
    Policy::CheckStatus(LsaRetrievePrivateData(policy.handle, &key, &value));
    if (!value) throw std::runtime_error("Missing Windows password.");
    const bool valid = value->Buffer && value->Length > 0 && value->Length % sizeof(wchar_t) == 0 &&
        value->Length < sizeof(password.value);
    if (valid) std::memcpy(password.value, value->Buffer, value->Length);
    if (value->Buffer) SecureZeroMemory(value->Buffer, value->Length);
    LsaFreeMemory(value);
    if (!valid) throw std::runtime_error("Invalid Windows password secret.");
}

void DeletePassword(std::wstring_view sid) {
    const auto name = SecretName(sid);
    auto key = LsaString(name);
    const Policy policy(POLICY_CREATE_SECRET);
    const auto status = LsaStorePrivateData(policy.handle, &key, nullptr);
    if (LsaNtStatusToWinError(status) != ERROR_FILE_NOT_FOUND) Policy::CheckStatus(status);
}

void RegisterProvider(const std::filesystem::path& dll) {
    const auto classPath = ClassKey() + L"\\InprocServer32";
    const RegistryKey registry(classPath.c_str());
    registry.Set(nullptr, dll.wstring());
    registry.Set(L"ThreadingModel", L"Apartment");
    RegistryKey(ProviderKey().c_str()).Set(nullptr, L"Unlock with phone");
}

void UnregisterProvider() {
    RemoveKey(ProviderKey());
    RemoveKey(ClassKey() + L"\\InprocServer32");
    RemoveKey(ClassKey());
}

}
