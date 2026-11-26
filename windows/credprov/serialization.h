#pragma once

#include "config.h"
#include <credentialprovider.h>

namespace quickunlock {

void Serialize(const Config& config, CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
               CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION& output);

}
