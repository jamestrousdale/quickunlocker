#include "webauthn.h"

#include <fstream>
#include <iostream>
#include <iterator>

using namespace quickunlock;

int main(int argc, char** argv) {
    if (argc != 2) return 1;
    const auto challenge = RandomChallenge();
    if (challenge == RandomChallenge() || DecodeBase64Url(EncodeBase64Url(challenge)) !=
        Bytes(challenge.begin(), challenge.end())) {
        std::cerr << "Challenge or base64url failed.\n";
        return 1;
    }
    if (Fingerprint({}) != "E3B0-C442-98FC-1C14-9AFB") {
        std::cerr << "Fingerprint failed.\n";
        return 1;
    }
    try {
        (void)ParseJson(R"({"duplicate":1,"duplicate":2})");
        std::cerr << "Duplicate JSON accepted.\n";
        return 1;
    } catch (const std::exception&) {}
    std::ifstream input(argv[1]);
    const std::string fixture{std::istreambuf_iterator<char>(input), {}};
    const auto cases = ParseJson(fixture);
    const auto bytes = DecodeBase64Url(cases.at("challenge").get<std::string>());
    if (bytes.size() != Digest{}.size()) return 1;
    Digest verifyChallenge{};
    std::copy(bytes.begin(), bytes.end(), verifyChallenge.begin());
    const auto rp = cases.at("rp_id").get<std::string>();
    const auto origin = cases.at("origin").get<std::string>();
    const Pins pins{{"dGVzdC1jcmVkZW50aWFs", DecodeBase64Url(cases.at("public_key").get<std::string>())}};
    for (const auto& [name, assertion] : cases.at("cases").items()) {
        if ((!VerifyAssertion(assertion, verifyChallenge, rp, origin, pins).empty()) != (name == "valid")) {
            std::cerr << "Unexpected result: " << name << '\n';
            return 1;
        }
    }
    return 0;
}
