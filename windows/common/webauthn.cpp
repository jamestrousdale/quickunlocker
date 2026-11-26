#include "webauthn.h"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <algorithm>
#include <cstring>
#include <set>
#include <stdexcept>

namespace quickunlock {
namespace {

void CheckCrypto(NTSTATUS status) {
    if (status < 0) {
        throw std::runtime_error("Windows cryptographic operation failed.");
    }
}

class Algorithm {
public:
    explicit Algorithm(LPCWSTR name) {
        CheckCrypto(BCryptOpenAlgorithmProvider(&handle, name, nullptr, 0));
    }
    ~Algorithm() { BCryptCloseAlgorithmProvider(handle, 0); }
    Algorithm(const Algorithm&) = delete;
    Algorithm& operator=(const Algorithm&) = delete;
    BCRYPT_ALG_HANDLE handle = nullptr;
};

class PublicKey {
public:
    PublicKey(const Algorithm& alg, std::span<const std::uint8_t> der) {
        // Canonical DER SPKI for id-ecPublicKey / prime256v1, with an uncompressed point.
        constexpr auto prefix = std::to_array<std::uint8_t>({
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        });
        if (der.size() != prefix.size() + 64 || !std::equal(prefix.begin(), prefix.end(), der.begin())) {
            throw std::runtime_error("Expected a P-256 SPKI public key.");
        }
        const BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32};
        std::array<std::uint8_t, sizeof(header) + 64> blob{};
        std::memcpy(blob.data(), &header, sizeof(header));
        std::copy(der.begin() + prefix.size(), der.end(), blob.begin() + sizeof(header));
        CheckCrypto(BCryptImportKeyPair(alg.handle, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                      &handle, blob.data(), static_cast<ULONG>(blob.size()), 0));
    }
    ~PublicKey() { BCryptDestroyKey(handle); }
    PublicKey(const PublicKey&) = delete;
    PublicKey& operator=(const PublicKey&) = delete;
    BCRYPT_KEY_HANDLE handle = nullptr;
};

class Hash {
public:
    explicit Hash(const Algorithm& alg) {
        CheckCrypto(BCryptCreateHash(alg.handle, &handle, nullptr, 0, nullptr, 0, 0));
    }
    ~Hash() { BCryptDestroyHash(handle); }
    Hash(const Hash&) = delete;
    Hash& operator=(const Hash&) = delete;
    BCRYPT_HASH_HANDLE handle = nullptr;
};

bool ReadInteger(std::span<const std::uint8_t>& input, std::span<std::uint8_t, 32> output) {
    if (input.size() < 3 || input[0] != 0x02) return false;
    const std::size_t length = input[1];
    if (length == 0 || length > 33 || length > input.size() - 2) return false;
    auto value = input.subspan(2, length);
    if (value[0] & 0x80) return false;
    if (value[0] == 0) {
        if (length == 1 || !(value[1] & 0x80)) return false;
        value = value.subspan(1);
    }
    if (value.size() > output.size()) return false;
    std::copy(value.begin(), value.end(), output.end() - value.size());
    input = input.subspan(length + 2);
    return true;
}

bool ReadSignature(std::span<const std::uint8_t> der, std::array<std::uint8_t, 64>& raw) {
    if (der.size() < 8 || der.size() > 72 || der[0] != 0x30 || der[1] != der.size() - 2) {
        return false;
    }
    auto integers = der.subspan(2);
    auto signature = std::span(raw);
    return ReadInteger(integers, signature.first<32>())
        && ReadInteger(integers, signature.last<32>()) && integers.empty();
}

std::span<const std::uint8_t> AsBytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

}

Digest RandomChallenge() {
    Digest result{};
    CheckCrypto(BCryptGenRandom(nullptr, result.data(), static_cast<ULONG>(result.size()),
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    return result;
}

Digest Sha256(std::span<const std::uint8_t> bytes) {
    Algorithm algorithm(BCRYPT_SHA256_ALGORITHM);
    Hash hash(algorithm);
    Digest result{};
    if (!bytes.empty()) {
        CheckCrypto(BCryptHashData(hash.handle, const_cast<PUCHAR>(bytes.data()),
                                  static_cast<ULONG>(bytes.size()), 0));
    }
    CheckCrypto(BCryptFinishHash(hash.handle, result.data(), static_cast<ULONG>(result.size()), 0));
    return result;
}

std::string EncodeBase64Url(std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) return {};
    constexpr DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    DWORD length = 0;
    if (!CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()), flags, nullptr, &length)) {
        throw std::runtime_error("Could not size base64 output.");
    }
    std::string text(length, '\0');
    if (!CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()), flags, text.data(), &length)) {
        throw std::runtime_error("Could not encode base64.");
    }
    text.resize(length);
    text.resize(text.find_last_not_of('=') + 1);
    std::replace(text.begin(), text.end(), '+', '-');
    std::replace(text.begin(), text.end(), '/', '_');
    return text;
}

Bytes DecodeBase64Url(std::string_view text) {
    if (text.empty() || text.size() > 65536 || text.size() % 4 == 1 ||
        text.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != text.npos) {
        throw std::runtime_error("Invalid base64url.");
    }
    std::string base64(text);
    std::replace(base64.begin(), base64.end(), '-', '+');
    std::replace(base64.begin(), base64.end(), '_', '/');
    base64.append((4 - base64.size() % 4) % 4, '=');
    DWORD length = 0;
    constexpr DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT;
    const auto inputLength = static_cast<DWORD>(base64.size());
    if (!CryptStringToBinaryA(base64.data(), inputLength, flags, nullptr, &length, nullptr, nullptr)) {
        throw std::runtime_error("Could not size decoded base64url.");
    }
    Bytes result(length);
    if (!CryptStringToBinaryA(base64.data(), inputLength, flags, result.data(), &length, nullptr, nullptr) ||
        EncodeBase64Url(result) != text) {
        throw std::runtime_error("Invalid canonical base64url.");
    }
    return result;
}

Json ParseJson(std::string_view text) {
    if (text.size() > 65536) throw std::runtime_error("JSON body is too large.");
    std::map<int, std::set<std::string>> objectKeys;
    return Json::parse(text, [&](int depth, Json::parse_event_t event, Json& value) {
        if (depth > 12) throw std::runtime_error("JSON body is too deeply nested.");
        if (event == Json::parse_event_t::object_start) objectKeys[depth + 1].clear();
        if (event == Json::parse_event_t::key &&
            !objectKeys[depth].insert(value.get<std::string>()).second) {
            throw std::runtime_error("Duplicate JSON member.");
        }
        return true;
    });
}

std::string Fingerprint(std::span<const std::uint8_t> spki) {
    const auto digest = Sha256(spki);
    constexpr std::string_view hex = "0123456789ABCDEF";
    std::string value;
    for (std::size_t i = 0; i < 10; ++i) {
        if (i && i % 2 == 0) value.push_back('-');
        value.push_back(hex[digest[i] >> 4]);
        value.push_back(hex[digest[i] & 15]);
    }
    return value;
}

bool IsP256Key(std::span<const std::uint8_t> spki) noexcept {
    try {
        const Algorithm alg(BCRYPT_ECDSA_P256_ALGORITHM);
        const PublicKey key(alg, spki);
        return true;
    } catch (...) {
        return false;
    }
}

std::string VerifyAssertion(const Json& assertion, const Digest& challenge,
                            std::string_view rpId, std::string_view origin, const Pins& pins) noexcept {
    try {
        const auto id = assertion.at("credential_id").get<std::string>();
        const auto pin = pins.find(id);
        if (pin == pins.end()) return {};

        const auto clientData = DecodeBase64Url(assertion.at("client_data_json").get<std::string>());
        auto authData = DecodeBase64Url(assertion.at("authenticator_data").get<std::string>());
        const auto der = DecodeBase64Url(assertion.at("signature").get<std::string>());
        const auto client = ParseJson({reinterpret_cast<const char*>(clientData.data()), clientData.size()});
        if (client.at("type") != "webauthn.get" || client.at("challenge") != EncodeBase64Url(challenge) ||
            client.at("origin") != origin || client.value("crossOrigin", false)) {
            return {};
        }
        const auto rpHash = Sha256(AsBytes(rpId));
        constexpr std::uint8_t requiredFlags = 0x05; // UP and UV
        if (authData.size() < 37 || !std::equal(rpHash.begin(), rpHash.end(), authData.begin()) ||
            (authData[32] & requiredFlags) != requiredFlags) {
            return {};
        }
        std::array<std::uint8_t, 64> signature{};
        if (!ReadSignature(der, signature)) return {};

        const Algorithm alg(BCRYPT_ECDSA_P256_ALGORITHM);
        const PublicKey key(alg, pin->second);
        const auto clientHash = Sha256(clientData);
        authData.insert(authData.end(), clientHash.begin(), clientHash.end());
        auto signedHash = Sha256(authData);
        if (BCryptVerifySignature(key.handle, nullptr, signedHash.data(),
                                  static_cast<ULONG>(signedHash.size()), signature.data(),
                                  static_cast<ULONG>(signature.size()), 0) < 0) return {};
        return id;
    } catch (...) {
        return {};
    }
}

}
