#include "config.h"

#include <credentialprovider.h>
#include <iostream>
#include <memory>
#include <string_view>

namespace {

using GetClassObject = HRESULT(WINAPI*)(REFCLSID, REFIID, void**);
using CanUnload = HRESULT(WINAPI*)();

struct Unload {
    void operator()(HMODULE module) const noexcept { FreeLibrary(module); }
};

struct Release {
    void operator()(IUnknown* object) const noexcept { object->Release(); }
};

bool VerifyProvider(ICredentialProvider& provider) {
    if (provider.SetUsageScenario(CPUS_CREDUI, 0) != E_NOTIMPL) return false;
    for (const auto scenario : {CPUS_LOGON, CPUS_UNLOCK_WORKSTATION}) {
        if (FAILED(provider.SetUsageScenario(scenario, 0))) return false;
        DWORD fields = 0;
        if (FAILED(provider.GetFieldDescriptorCount(&fields)) || fields != 2) return false;

        // Without an advised LogonUI and a matching account, the provider
        // enumerates no tile and allows Windows' standard providers to proceed.
        DWORD credentials = 1, index = 0;
        BOOL autoLogon = TRUE;
        if (FAILED(provider.GetCredentialCount(&credentials, &index, &autoLogon)) ||
            credentials != 0 || index != CREDENTIAL_PROVIDER_NO_DEFAULT || autoLogon) return false;
    }
    return true;
}

bool VerifyFactory(GetClassObject getClass, CanUnload canUnload) {
    if (canUnload() != S_OK) return false;
    IClassFactory* rawFactory = nullptr;
    if (FAILED(getClass(quickunlock::ProviderId, IID_IClassFactory, reinterpret_cast<void**>(&rawFactory)))) {
        return false;
    }
    const std::unique_ptr<IClassFactory, Release> factory(rawFactory);
    ICredentialProvider* rawProvider = nullptr;
    if (FAILED(factory->CreateInstance(nullptr, IID_ICredentialProvider, reinterpret_cast<void**>(&rawProvider)))) {
        return false;
    }
    const std::unique_ptr<ICredentialProvider, Release> provider(rawProvider);
    return canUnload() == S_FALSE && VerifyProvider(*provider);
}

}

int wmain(int argc, wchar_t** argv) {
    const bool underCoverage = argc == 3 && std::wstring_view(argv[2]) == L"coverage";
    if (argc != 2 && !underCoverage) return 1;
    // The collector adds its native runtime directory to the child process PATH.
    const DWORD search = underCoverage ? 0 : LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
    const std::unique_ptr<std::remove_pointer_t<HMODULE>, Unload> module(
        LoadLibraryExW(argv[1], nullptr, search));
    if (!module) {
        std::cerr << "Could not load credential provider DLL: " << GetLastError() << '\n';
        return 1;
    }
    const auto getClass = reinterpret_cast<GetClassObject>(GetProcAddress(module.get(), "DllGetClassObject"));
    const auto canUnload = reinterpret_cast<CanUnload>(GetProcAddress(module.get(), "DllCanUnloadNow"));
    if (!getClass || !canUnload || !VerifyFactory(getClass, canUnload) || canUnload() != S_OK) {
        std::cerr << "Credential provider COM smoke test failed.\n";
        return 1;
    }
    return 0;
}
