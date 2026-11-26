#include "config.h"
#include "http.h"
#include "serialization.h"

#include <credentialprovider.h>
#include <shlguid.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>

using namespace quickunlock;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

namespace {

std::atomic_long objects{0};

class ModuleObject {
public:
    ModuleObject() { ++objects; }
    ~ModuleObject() { --objects; }
};

template<class T>
struct Release {
    void operator()(T* object) const noexcept { object->Release(); }
};

template<class T>
using ComPtr = std::unique_ptr<T, Release<T>>;

struct FreeCom {
    void operator()(void* value) const noexcept { CoTaskMemFree(value); }
};

template<class T>
HRESULT CopyString(std::wstring_view text, T** out) noexcept {
    auto value = static_cast<wchar_t*>(CoTaskMemAlloc((text.size() + 1) * sizeof(wchar_t)));
    if (!value) return E_OUTOFMEMORY;
    std::memcpy(value, text.data(), text.size() * sizeof(wchar_t));
    value[text.size()] = L'\0';
    *out = value;
    return S_OK;
}

HRESULT OpenGit(IGlobalInterfaceTable** git) {
    return CoCreateInstance(CLSID_StdGlobalInterfaceTable, nullptr, CLSCTX_INPROC_SERVER,
                            IID_IGlobalInterfaceTable, reinterpret_cast<void**>(git));
}

struct Approval {
    std::string credential;
    Clock::time_point until{};
};

struct Attempt {
    Config config;
    std::atomic_bool stopped{false};
    std::mutex mutex;
    Approval approval;
    DWORD cookie = 0;
    UINT_PTR adviseContext = 0;

    bool Ready() {
        std::scoped_lock lock(mutex);
        return !stopped && !approval.credential.empty() && Clock::now() < approval.until;
    }

    Approval Take() {
        std::scoped_lock lock(mutex);
        if (approval.credential.empty() || Clock::now() >= approval.until || stopped.exchange(true)) return {};
        return std::exchange(approval, {});
    }
};

void Notify(const Attempt& attempt) {
    if (attempt.stopped) return;
    IGlobalInterfaceTable* rawGit = nullptr;
    if (FAILED(OpenGit(&rawGit))) return;
    ComPtr<IGlobalInterfaceTable> git(rawGit);
    ICredentialProviderEvents* rawEvents = nullptr;
    const auto hr = git->GetInterfaceFromGlobal(attempt.cookie, IID_ICredentialProviderEvents,
                                                reinterpret_cast<void**>(&rawEvents));
    ComPtr<ICredentialProviderEvents> events(rawEvents);
    if (SUCCEEDED(hr) && !attempt.stopped) (void)events->CredentialsChanged(attempt.adviseContext);
}

void AwaitPhone(Attempt& attempt) {
    while (!attempt.stopped) {
        try {
            const Config& config = attempt.config;
            const HttpClient relay(config.origin);
            const auto challenge = RandomChallenge();
            const auto until = Clock::now() + 90s;
            const auto start = relay.Post("/api/unlock-requests", {
                {"pc_name", config.pcName}, {"challenge", EncodeBase64Url(challenge)},
            });
            const auto id = start.at("id").get<std::string>();
            if (!IsCapability(id)) throw std::runtime_error("Invalid unlock request ID.");

            while (!attempt.stopped && Clock::now() < until) {
                const auto result = relay.Get("/api/unlock-requests/" + id + "?wait=5");
                const auto status = result.at("status").get<std::string>();
                if (status == "pending") {
                    Sleep(250);
                    continue;
                }
                if (status == "expired") break;
                if (status != "approved") throw std::runtime_error("Invalid unlock request status.");

                auto credential = VerifyAssertion(result.at("assertion"), challenge, config.rpId,
                                                  config.origin, config.pins);
                if (credential.empty()) throw std::runtime_error("Passkey verification failed.");
                {
                    std::scoped_lock lock(attempt.mutex);
                    if (attempt.stopped || Clock::now() >= until) break;
                    attempt.approval = {std::move(credential), until};
                }
                Notify(attempt);
                while (!attempt.stopped && attempt.Ready()) Sleep(250);
                if (attempt.stopped) return;
                break;
            }
            if (!attempt.stopped) Sleep(250);
        } catch (...) {
            // Network and protocol failures must leave the system providers usable.
            for (int elapsed = 0; elapsed < 20 && !attempt.stopped; ++elapsed) Sleep(250);
        }
    }
}

struct ThreadWork {
    std::shared_ptr<Attempt> attempt;
    HMODULE module;
};

DWORD WINAPI RunWorker(void* argument) {
    HMODULE module;
    {
        const std::unique_ptr<ThreadWork> work(static_cast<ThreadWork*>(argument));
        module = work->module;
        if (SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) {
            AwaitPhone(*work->attempt);
            CoUninitialize();
        }
    }
    FreeLibraryAndExitThread(module, 0);
}

class Credential final : public ICredentialProviderCredential2, private ModuleObject {
public:
    Credential(std::shared_ptr<Attempt> attempt, CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario)
        : attempt_(std::move(attempt)), scenario_(scenario) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** result) override {
        *result = nullptr;
        if (iid != IID_IUnknown && iid != IID_ICredentialProviderCredential &&
            iid != IID_ICredentialProviderCredential2) return E_NOINTERFACE;
        *result = static_cast<ICredentialProviderCredential2*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto count = --refs_;
        if (!count) delete this;
        return count;
    }

    HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderCredentialEvents*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE UnAdvise() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetSelected(BOOL* autoLogon) override {
        *autoLogon = attempt_->Ready();
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetDeselected() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetUserSid(PWSTR* sid) override { return CopyString(attempt_->config.sid, sid); }

    HRESULT STDMETHODCALLTYPE GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* state,
                                             CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) override {
        if (id > 1) return E_INVALIDARG;
        *state = CPFS_DISPLAY_IN_BOTH;
        *interactive = CPFIS_NONE;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetStringValue(DWORD id, PWSTR* value) override {
        return id == 0 ? CopyString(L"Unlock with phone", value) : E_INVALIDARG;
    }
    HRESULT STDMETHODCALLTYPE GetBitmapValue(DWORD id, HBITMAP* result) override {
        *result = nullptr;
        if (id != 1) return E_INVALIDARG;
        const HICON icon = LoadIconW(nullptr, IDI_SHIELD);
        if (!icon) return E_FAIL;
        ICONINFO image{};
        if (!GetIconInfo(icon, &image)) return E_FAIL;
        if (image.hbmMask) DeleteObject(image.hbmMask);
        *result = image.hbmColor;
        return *result ? S_OK : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE GetCheckboxValue(DWORD, BOOL*, PWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(DWORD, DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(DWORD, DWORD*, DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(DWORD, DWORD, PWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetStringValue(DWORD, PCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(DWORD, DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD) override { return E_NOTIMPL; }

    HRESULT STDMETHODCALLTYPE GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                                               CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* output,
                                               PWSTR* text, CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
        *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        *output = {};
        *text = nullptr;
        *icon = CPSI_NONE;
        try {
            const auto approval = attempt_->Take();
            if (approval.credential.empty() || Clock::now() >= approval.until) return S_OK;
            const auto current = LoadConfig();
            if (!current || *current != attempt_->config) return S_OK;
            Serialize(*current, scenario_, *output);
            *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
        } catch (...) {
            // Windows password and PIN providers remain available.
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ReportResult(NTSTATUS status, NTSTATUS, PWSTR* text,
                                            CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
        *text = nullptr;
        *icon = CPSI_NONE;
        if (status != 0) {
            *icon = CPSI_ERROR;
            return CopyString(L"Phone sign-in failed. Use your Windows password or PIN.", text);
        }
        return S_OK;
    }

private:
    std::atomic_ulong refs_{1};
    std::shared_ptr<Attempt> attempt_;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
};

class Provider final : public ICredentialProvider, public ICredentialProviderSetUserArray, private ModuleObject {
public:
    ~Provider() { UnAdvise(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** result) override {
        *result = nullptr;
        if (iid == IID_IUnknown || iid == IID_ICredentialProvider) {
            *result = static_cast<ICredentialProvider*>(this);
        } else if (iid == IID_ICredentialProviderSetUserArray) {
            *result = static_cast<ICredentialProviderSetUserArray*>(this);
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto count = --refs_;
        if (!count) delete this;
        return count;
    }

    HRESULT STDMETHODCALLTYPE SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD) override {
        if (scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION) return E_NOTIMPL;
        if (scenario != scenario_) Stop();
        scenario_ = scenario;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderEvents* events, UINT_PTR context) override {
        UnAdvise();
        IGlobalInterfaceTable* git = nullptr;
        if (FAILED(OpenGit(&git))) return S_OK;
        git_.reset(git);
        if (FAILED(git_->RegisterInterfaceInGlobal(events, IID_ICredentialProviderEvents, &cookie_))) {
            git_.reset();
            return S_OK;
        }
        context_ = context;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE UnAdvise() override {
        Stop();
        if (cookie_ && git_) git_->RevokeInterfaceFromGlobal(cookie_);
        cookie_ = 0;
        git_.reset();
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetUserArray(ICredentialProviderUserArray* users) override {
        if (users) users->AddRef();
        users_.reset(users);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(DWORD* count) override {
        *count = 2;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(DWORD id, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out) override {
        *out = nullptr;
        if (id > 1) return E_INVALIDARG;
        auto descriptor = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
            CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
        if (!descriptor) return E_OUTOFMEMORY;
        *descriptor = id == 0
            ? CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR{0, CPFT_SMALL_TEXT, nullptr, CPFG_CREDENTIAL_PROVIDER_LABEL}
            : CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR{1, CPFT_TILE_IMAGE, nullptr, CPFG_CREDENTIAL_PROVIDER_LOGO};
        const auto hr = CopyString(id == 0 ? L"Unlock with phone" : L"Phone sign-in", &descriptor->pszLabel);
        if (FAILED(hr)) {
            CoTaskMemFree(descriptor);
            return hr;
        }
        *out = descriptor;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogon) override {
        *count = 0;
        *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *autoLogon = FALSE;
        try {
            const auto config = LoadConfig();
            if (!users_ || !cookie_ || !config || config->pins.empty() || !HasUser(config->sid)) {
                Stop();
                return S_OK;
            }
            if (attempt_ && attempt_->config != *config) Stop();
            if (!attempt_) Start(*config);
            if (credential_) {
                *count = 1;
                if (attempt_->Ready()) {
                    *defaultIndex = 0;
                    *autoLogon = TRUE;
                }
            }
        } catch (...) {
            Stop();
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetCredentialAt(DWORD index, ICredentialProviderCredential** out) override {
        *out = nullptr;
        if (index != 0 || !credential_) return E_INVALIDARG;
        credential_->AddRef();
        *out = credential_.get();
        return S_OK;
    }

private:
    bool HasUser(std::wstring_view configuredSid) {
        DWORD count = 0;
        if (FAILED(users_->GetCount(&count))) return false;
        for (DWORD i = 0; i < count; ++i) {
            ICredentialProviderUser* rawUser = nullptr;
            if (FAILED(users_->GetAt(i, &rawUser))) continue;
            const ComPtr<ICredentialProviderUser> user(rawUser);
            PWSTR rawSid = nullptr;
            if (FAILED(user->GetSid(&rawSid))) continue;
            const std::unique_ptr<wchar_t, FreeCom> sid(rawSid);
            if (sid && configuredSid == sid.get()) return true;
        }
        return false;
    }

    void Start(const Config& config) {
        auto attempt = std::make_shared<Attempt>();
        attempt->config = config;
        attempt->cookie = cookie_;
        attempt->adviseContext = context_;
        ComPtr<Credential> credential(new Credential(attempt, scenario_));
        auto work = std::make_unique<ThreadWork>(ThreadWork{attempt, nullptr});
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                reinterpret_cast<LPCWSTR>(&objects), &work->module)) return;
        // The thread owns this allocation and the module reference after a successful launch.
        auto rawWork = work.release();
        const HANDLE thread = CreateThread(nullptr, 0, RunWorker, rawWork, 0, nullptr);
        if (!thread) {
            FreeLibrary(rawWork->module);
            delete rawWork;
            return;
        }
        CloseHandle(thread);
        attempt_ = std::move(attempt);
        credential_ = std::move(credential);
    }

    void Stop() noexcept {
        if (attempt_) attempt_->stopped = true;
        credential_.reset();
        attempt_.reset();
    }

    std::atomic_ulong refs_{1};
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_ = CPUS_INVALID;
    ComPtr<ICredentialProviderUserArray> users_;
    ComPtr<IGlobalInterfaceTable> git_;
    DWORD cookie_ = 0;
    UINT_PTR context_ = 0;
    std::shared_ptr<Attempt> attempt_;
    ComPtr<Credential> credential_;
};

class Factory final : public IClassFactory, private ModuleObject {
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** result) override {
        *result = nullptr;
        if (iid != IID_IUnknown && iid != IID_IClassFactory) return E_NOINTERFACE;
        *result = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto count = --refs_;
        if (!count) delete this;
        return count;
    }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** result) override {
        *result = nullptr;
        if (outer) return CLASS_E_NOAGGREGATION;
        const ComPtr<Provider> provider(new (std::nothrow) Provider());
        return provider ? provider->QueryInterface(iid, result) : E_OUTOFMEMORY;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock) ++objects;
        else --objects;
        return S_OK;
    }

private:
    std::atomic_ulong refs_{1};
};

}

extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void** result) {
    *result = nullptr;
    if (clsid != ProviderId) return CLASS_E_CLASSNOTAVAILABLE;
    const ComPtr<Factory> factory(new (std::nothrow) Factory());
    return factory ? factory->QueryInterface(iid, result) : E_OUTOFMEMORY;
}

extern "C" HRESULT WINAPI DllCanUnloadNow() {
    return objects == 0 ? S_OK : S_FALSE;
}
