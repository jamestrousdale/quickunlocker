#pragma once

#include "config.h"

namespace quickunlock {

struct EnrollmentSession {
    std::string id;
    std::string url;
};

struct EnrollmentKey {
    std::string credential;
    Bytes spki;
};

EnrollmentSession ParseEnrollmentSession(const Json& payload, std::string_view origin);
EnrollmentKey ParseEnrollmentKey(const Json& payload);
void ConfirmEnrollmentKey(Pins& pins, EnrollmentKey key, std::string_view entered);

}
