#ifndef OPENDNP3_SAMODE_H
#define OPENDNP3_SAMODE_H

#include <cstdint>

namespace opendnp3 {

enum class SAMode : uint8_t
{
    NONE = 0,   // SA вимкнено
    SAV2 = 2,   // Secure Authentication v2 (16-byte Update Key)
    SAV5 = 5    // Secure Authentication v5 (32-byte Update Key, IEEE 1815-2012)
};

}
#endif // OPENDNP3_SAMODE_H