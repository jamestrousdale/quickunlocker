#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>

namespace quickunlock {

using Bytes = std::vector<std::uint8_t>;
using Digest = std::array<std::uint8_t, 32>;
using Pins = std::map<std::string, Bytes, std::less<>>;
using Json = nlohmann::json;

Digest RandomChallenge();
Digest Sha256(std::span<const std::uint8_t> bytes);
std::string EncodeBase64Url(std::span<const std::uint8_t> bytes);
Bytes DecodeBase64Url(std::string_view text);
Json ParseJson(std::string_view text);
std::string Fingerprint(std::span<const std::uint8_t> spki);
bool IsP256Key(std::span<const std::uint8_t> spki) noexcept;

// An empty result is a failed verification. The assertion is untrusted.
std::string VerifyAssertion(const Json& assertion, const Digest& challenge,
                            std::string_view rpId, std::string_view origin, const Pins& pins) noexcept;

}
