#include "serialization.h"

#include <ntsecapi.h>
#include <wincred.h>

#include <cstring>
#include <stdexcept>

namespace quickunlock {
namespace {

ULONG NegotiatePackage() {
    LSA_HANDLE lsa = nullptr;
    if (LsaConnectUntrusted(&lsa) < 0) throw std::runtime_error("Could not connect to LSA.");
    char name[] = "Negotiate";
    LSA_STRING package{sizeof(name) - 1, sizeof(name), name};
    ULONG number = 0;
    const auto status = LsaLookupAuthenticationPackage(lsa, &package, &number);
    LsaDeregisterLogonProcess(lsa);
    if (status < 0) throw std::runtime_error("Could not find Negotiate.");
    return number;
}

class ProtectedPassword {
public:
    explicit ProtectedPassword(Password& password) {
        const auto size = static_cast<DWORD>(wcslen(password.value) + 1);
        DWORD length = 0;
        if (CredProtectW(FALSE, password.value, size, nullptr, &length, nullptr) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER || length == 0 || length > 8192) {
            throw std::runtime_error("Could not size protected Windows password.");
        }
        value.resize(length);
        if (!CredProtectW(FALSE, password.value, size, value.data(), &length, nullptr)) {
            Wipe();
            throw std::runtime_error("Could not protect Windows password.");
        }
    }
    ~ProtectedPassword() { Wipe(); }
    ProtectedPassword(const ProtectedPassword&) = delete;
    ProtectedPassword& operator=(const ProtectedPassword&) = delete;

    std::wstring_view View() const { return value.data(); }

private:
    void Wipe() noexcept { SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t)); }
    std::vector<wchar_t> value;
};

}

void Serialize(const Config& config, CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
               CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION& output) {
    const ULONG package = NegotiatePackage();
    Password password;
    LoadPassword(config.sid, password);
    const ProtectedPassword protectedPassword(password);
    const auto secret = protectedPassword.View();
    const auto total = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) +
        (config.domain.size() + config.username.size() + secret.size()) * sizeof(wchar_t);
    auto buffer = static_cast<BYTE*>(CoTaskMemAlloc(total));
    if (!buffer) throw std::bad_alloc();
    auto logon = new (buffer) KERB_INTERACTIVE_UNLOCK_LOGON{};
    logon->Logon.MessageType = scenario == CPUS_LOGON ? KerbInteractiveLogon : KerbWorkstationUnlockLogon;

    std::size_t offset = sizeof(*logon);
    const auto pack = [&](UNICODE_STRING& field, std::wstring_view text) {
        const auto size = text.size() * sizeof(wchar_t);
        std::memcpy(buffer + offset, text.data(), size);
        field.Length = field.MaximumLength = static_cast<USHORT>(size);
        field.Buffer = reinterpret_cast<PWSTR>(offset);
        offset += size;
    };
    pack(logon->Logon.LogonDomainName, config.domain);
    pack(logon->Logon.UserName, config.username);
    pack(logon->Logon.Password, secret);

    output.ulAuthenticationPackage = package;
    output.clsidCredentialProvider = ProviderId;
    output.cbSerialization = static_cast<ULONG>(total);
    output.rgbSerialization = buffer;
}

}
