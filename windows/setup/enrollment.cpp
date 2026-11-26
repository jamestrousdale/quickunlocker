#include "enrollment.h"
#include "http.h"

#include <algorithm>
#include <stdexcept>

namespace quickunlock {

EnrollmentSession ParseEnrollmentSession(const Json& payload, std::string_view origin) {
    EnrollmentSession session{payload.at("session_id").get<std::string>(), payload.at("enroll_url").get<std::string>()};
    const auto prefix = std::string(origin) + "/enroll?s=";
    if (!IsCapability(session.id) || !session.url.starts_with(prefix) ||
        !IsCapability(std::string_view(session.url).substr(prefix.size()))) {
        throw std::runtime_error("Relay returned an invalid enrollment link.");
    }
    return session;
}

EnrollmentKey ParseEnrollmentKey(const Json& payload) {
    EnrollmentKey key{
        payload.at("credential_id").get<std::string>(),
        DecodeBase64Url(payload.at("spki_der").get<std::string>()),
    };
    (void)DecodeBase64Url(key.credential);
    if (!IsP256Key(key.spki)) throw std::runtime_error("Expected an ES256 passkey.");
    return key;
}

void ConfirmEnrollmentKey(Pins& pins, EnrollmentKey key, std::string_view entered) {
    auto fingerprint = std::string(entered);
    std::transform(fingerprint.begin(), fingerprint.end(), fingerprint.begin(), [](char c) {
        return static_cast<char>(c >= 'a' && c <= 'f' ? c - 'a' + 'A' : c);
    });
    if (fingerprint != Fingerprint(key.spki)) throw std::runtime_error("Fingerprint mismatch.");
    const auto old = pins.find(key.credential);
    if (old != pins.end() && old->second != key.spki) throw std::runtime_error("Credential ID already pinned.");
    pins.insert_or_assign(std::move(key.credential), std::move(key.spki));
}

}
