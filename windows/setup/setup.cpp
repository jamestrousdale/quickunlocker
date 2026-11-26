#include <winsock2.h>
#include <ws2tcpip.h>
#include "config.h"
#include "http.h"
#include "enrollment.h"

#include <iphlpapi.h>
#include <netioapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <qrcodegen.hpp>

#include <chrono>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>

using namespace quickunlock;
using namespace std::chrono_literals;

namespace {

struct CloseHandlePtr {
    void operator()(void* handle) const noexcept { CloseHandle(handle); }
};
struct FreeLocal {
    void operator()(void* value) const noexcept { LocalFree(value); }
};
struct FreeCom {
    void operator()(void* value) const noexcept { CoTaskMemFree(value); }
};

std::wstring Prompt(const wchar_t* label) {
    std::wcout << label << std::flush;
    std::wstring value;
    if (!std::getline(std::wcin, value)) throw std::runtime_error("Input cancelled.");
    return value;
}

void RequireAdmin() {
    BOOL admin = FALSE;
    BYTE group[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(group);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, group, &size) ||
        !CheckTokenMembership(nullptr, group, &admin) || !admin) {
        throw std::runtime_error("Run this tool from an elevated terminal.");
    }
}

void ReadPassword(Password& password) {
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0, read = 0;
    if (!GetConsoleMode(input, &mode) || !SetConsoleMode(input, mode & ~ENABLE_ECHO_INPUT)) {
        throw std::runtime_error("Password entry requires an interactive console.");
    }
    std::wcout << L"Windows password: " << std::flush;
    const BOOL ok = ReadConsoleW(input, password.value, std::size(password.value) - 1, &read, nullptr);
    SetConsoleMode(input, mode);
    std::wcout << L'\n';
    if (!ok || read < 2 || password.value[read - 1] != L'\n') {
        throw std::runtime_error("Invalid password input.");
    }
    while (read && (password.value[read - 1] == L'\r' || password.value[read - 1] == L'\n')) {
        password.value[--read] = L'\0';
    }
    if (!read) throw std::runtime_error("A Windows password is required.");
}

std::wstring ValidateAccount(const std::wstring& domain, const std::wstring& user, const Password& password) {
    HANDLE rawToken = nullptr;
    if (!LogonUserW(user.c_str(), domain.c_str(), password.value,
                    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &rawToken)) {
        throw std::runtime_error("Windows rejected the account or password.");
    }
    std::unique_ptr<void, CloseHandlePtr> token(rawToken);
    DWORD size = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    Bytes data(size);
    if (!size || !GetTokenInformation(token.get(), TokenUser, data.data(), size, &size)) {
        throw std::runtime_error("Could not read the Windows account SID.");
    }
    PWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &sid)) {
        throw std::runtime_error("Could not format the Windows account SID.");
    }
    const std::unique_ptr<wchar_t, FreeLocal> ownedSid(sid);
    return ownedSid.get();
}

std::string ComputerName() {
    wchar_t value[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD length = std::size(value);
    if (!GetComputerNameW(value, &length)) throw std::runtime_error("Could not read the PC name.");
    return ToUtf8({value, length});
}

std::string WiredMac() {
    ULONG size = 15000;
    Bytes storage(size);
    constexpr ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    ULONG status = ERROR_BUFFER_OVERFLOW;
    PIP_ADAPTER_ADDRESSES first = nullptr;
    for (int attempt = 0; attempt < 3 && status == ERROR_BUFFER_OVERFLOW; ++attempt) {
        storage.resize(size);
        first = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(storage.data());
        status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, first, &size);
    }
    if (status != NO_ERROR) throw std::runtime_error("Could not enumerate network adapters.");

    const IP_ADAPTER_ADDRESSES* selected = nullptr;
    for (auto adapter = first; adapter; adapter = adapter->Next) {
        if (adapter->IfType != IF_TYPE_ETHERNET_CSMACD || adapter->OperStatus != IfOperStatusUp ||
            adapter->PhysicalAddressLength != 6 || !adapter->FirstUnicastAddress) continue;
        MIB_IF_ROW2 row{};
        row.InterfaceLuid = adapter->Luid;
        if (GetIfEntry2(&row) != NO_ERROR || !row.InterfaceAndOperStatusFlags.HardwareInterface) continue;
        selected = adapter;
        if (adapter->FirstGatewayAddress) break;
    }
    if (!selected) throw std::runtime_error("Connect an active wired Ethernet adapter to enroll.");
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i) out << ':';
        out << std::setw(2) << static_cast<unsigned>(selected->PhysicalAddress[i]);
    }
    return out.str();
}

void ShowQr(const std::string& url) {
    const auto qr = qrcodegen::QrCode::encodeText(url.c_str(), qrcodegen::QrCode::Ecc::LOW);
    // Use the console's own attributes so redirected output contains no escape codes.
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO state{};
    const int width = (qr.getSize() + 8) * 2;
    if (GetConsoleScreenBufferInfo(output, &state) && state.dwSize.X > width) {
        std::wcout.flush();
        for (int y = -4; y < qr.getSize() + 4; ++y) {
            for (int x = -4; x < qr.getSize() + 4; ++x) {
                constexpr WORD white = BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE | BACKGROUND_INTENSITY;
                SetConsoleTextAttribute(output, qr.getModule(x, y) ? 0 : white);
                DWORD written = 0;
                WriteConsoleW(output, L"  ", 2, &written, nullptr);
            }
            SetConsoleTextAttribute(output, state.wAttributes);
            DWORD written = 0;
            WriteConsoleW(output, L"\r\n", 2, &written, nullptr);
        }
    }
    std::wcout << L"Open on your phone: " << ToWide(url) << L'\n';
}

void Enroll(Config& config, const HttpClient& relay) {
    if (config.pins.size() >= 32) throw std::runtime_error("Revoke a key before enrolling another.");
    const auto mac = WiredMac();
    std::wcout << L"Enrolling " << ToWide(config.pcName) << L" with wired MAC " << ToWide(mac) << L'\n';
    const auto session = ParseEnrollmentSession(
        relay.Post("/api/enroll/sessions", {{"pc_name", config.pcName}, {"mac", mac}}), config.origin);
    const auto deadline = std::chrono::steady_clock::now() + 5min;
    ShowQr(session.url);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto response = relay.Get("/api/enroll/sessions/" + session.id + "?wait=25", 35000);
        const auto& status = response.at("status").get_ref<const std::string&>();
        if (status == "pending") continue;
        if (status != "complete" || std::chrono::steady_clock::now() >= deadline) break;
        auto key = ParseEnrollmentKey(response);
        std::wcout << L"PC fingerprint: " << ToWide(Fingerprint(key.spki)) << L'\n';
        const auto entered = ToUtf8(Prompt(L"Type the fingerprint shown on your phone: "));
        ConfirmEnrollmentKey(config.pins, std::move(key), entered);
        return;
    }
    throw std::runtime_error("Enrollment expired.");
}

void Configure(std::optional<Config> previous) {
    Config config = previous.value_or(Config{});
    const auto enteredOrigin = Prompt(L"Relay HTTPS origin (blank keeps current): ");
    if (!enteredOrigin.empty()) config.origin = ToUtf8(enteredOrigin);
    const HttpClient relay(config.origin);
    if (previous && !previous->pins.empty() && config.origin != previous->origin) {
        throw std::runtime_error("Revoke existing pins before changing the relay.");
    }
    config.rpId = relay.Host();
    config.pcName = ComputerName();

    const auto account = Prompt(L"Windows account (for example .\\yourname): ");
    const auto split = account.find(L'\\');
    if (split == account.npos || split == 0 || split == account.size() - 1) {
        throw std::runtime_error("Enter a domain and username separated by a backslash.");
    }
    config.domain = account.substr(0, split);
    if (config.domain == L".") config.domain = ToWide(config.pcName);
    config.username = account.substr(split + 1);

    Password password;
    ReadPassword(password);
    config.sid = ValidateAccount(config.domain, config.username, password);
    if (previous && config.sid != previous->sid && !previous->pins.empty()) {
        throw std::runtime_error("Revoke existing pins before changing the Windows account.");
    }
    Enroll(config, relay);
    StorePassword(config.sid, password);
    SaveConfig(config);
    if (previous && config.sid != previous->sid) DeletePassword(previous->sid);
    std::wcout << L"Passkey pinned. Run register to enable the tile.\n";
}

void Install() {
    const auto config = LoadConfig();
    if (!config || config->pins.empty()) throw std::runtime_error("Configure and enroll first.");
    PWSTR rawFolder = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &rawFolder))) {
        throw std::runtime_error("Could not locate Program Files.");
    }
    const std::unique_ptr<wchar_t, FreeCom> folder(rawFolder);
    const auto target = std::filesystem::path(folder.get()) / L"Quickunlocker";
    std::wstring exe(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, exe.data(), static_cast<DWORD>(exe.size()));
    if (!length || length == exe.size()) throw std::runtime_error("Could not locate setup executable.");
    exe.resize(length);
    const auto source = std::filesystem::path(exe).parent_path() / L"quickunlocker.dll";
    const auto destination = target / L"quickunlocker.dll";
    std::filesystem::create_directories(target);
    if (source != destination) {
        std::filesystem::copy_file(source, destination, std::filesystem::copy_options::overwrite_existing);
    }
    RegisterProvider(destination);
    std::wcout << L"Provider registered. Keep your Windows password or PIN available.\n";
}

}

int wmain(int argc, wchar_t* argv[]) {
    try {
        RequireAdmin();
        const std::wstring_view command = argc >= 2 ? argv[1] : L"";
        if (command == L"configure") {
            Configure(LoadConfig());
        } else if (command == L"register") {
            Install();
        } else if (command == L"unregister") {
            UnregisterProvider();
            auto config = LoadConfig();
            if (config) {
                DeletePassword(config->sid);
                config->pins.clear();
                SaveConfig(*config);
            }
            std::wcout << L"Provider unregistered. Enrolled pins and local password removed.\n";
        } else if (command == L"list" || (command == L"revoke" && argc == 3) ||
                   command == L"enroll" || command == L"password") {
            auto config = LoadConfig();
            if (!config) throw std::runtime_error("Configure the PC first.");
            if (command == L"list") {
                for (const auto& [id, key] : config->pins) {
                    std::wcout << ToWide(id) << L"  " << ToWide(Fingerprint(key)) << L'\n';
                }
            } else if (command == L"revoke") {
                if (!config->pins.erase(ToUtf8(argv[2]))) throw std::runtime_error("Unknown credential ID.");
                SaveConfig(*config);
            } else if (command == L"enroll") {
                Enroll(*config, HttpClient(config->origin));
                SaveConfig(*config);
            } else {
                Password password;
                ReadPassword(password);
                if (ValidateAccount(config->domain, config->username, password) != config->sid) {
                    throw std::runtime_error("The account SID has changed.");
                }
                StorePassword(config->sid, password);
            }
        } else {
            std::wcout << L"Usage: quickunlocker-setup configure|enroll|list|revoke ID|password|register|unregister\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
