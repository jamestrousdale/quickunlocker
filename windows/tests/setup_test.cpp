#include "enrollment.h"

#include <fstream>
#include <iostream>
#include <iterator>

using namespace quickunlock;

template<class Operation>
bool Rejected(Operation&& operation) {
    try { operation(); } catch (const std::exception&) { return true; }
    return false;
}

int main(int argc, char** argv) {
    if (argc != 2) return 1;
    std::ifstream input(argv[1]);
    const std::string fixture{std::istreambuf_iterator<char>(input), {}};
    const auto data = ParseJson(fixture);
    const auto origin = data.at("origin").get<std::string>();
    const auto id = std::string(32, 'a');
    const auto url = origin + "/enroll?s=" + std::string(32, 'b');
    const Json session{{"session_id", id}, {"enroll_url", url}};
    const auto parsed = ParseEnrollmentSession(session, origin);
    if (parsed.id != id || parsed.url != url) return 1;

    auto unexpected = session;
    unexpected["enroll_url"] = "https://other.example.com/enroll?s=" + std::string(32, 'b');
    if (!Rejected([&] { (void)ParseEnrollmentSession(unexpected, origin); })) return 1;
    unexpected["enroll_url"] = url + "&other=1";
    if (!Rejected([&] { (void)ParseEnrollmentSession(unexpected, origin); })) return 1;

    const Json payload{{"credential_id", "dGVzdC1jcmVkZW50aWFs"}, {"spki_der", data.at("public_key")}};
    const auto key = ParseEnrollmentKey(payload);
    Pins pins;
    if (!Rejected([&] { ConfirmEnrollmentKey(pins, key, "wrong"); }) || !pins.empty()) return 1;
    ConfirmEnrollmentKey(pins, key, Fingerprint(key.spki));
    if (pins.at(key.credential) != key.spki) return 1;
    pins.at(key.credential) = {0};
    if (!Rejected([&] { ConfirmEnrollmentKey(pins, key, Fingerprint(key.spki)); })) return 1;
    return 0;
}
