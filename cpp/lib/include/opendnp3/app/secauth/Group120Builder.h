/*
 * Copyright (c) 2026 parumsancto/opendnp3
 *
 * DNP3 Secure Authentication Group 120 Builder
 * Constructs raw DNP3 APDU fragments for Group 120 objects
 */

#ifndef OPENDNP3_GROUP120BUILDER_H
#define OPENDNP3_GROUP120BUILDER_H

#include "opendnp3/app/secauth/Group120.h"
#include "opendnp3/app/AppConstants.h"
#include "opendnp3/gen/FunctionCode.h"
#include <vector>
#include <cstdint>

namespace opendnp3
{

/**
 * @brief Builder for DNP3 Group 120 objects
 * @details Generates complete APDU fragments with object headers
 */
class Group120Builder
{
public:
    /**
     * @brief Build g120v1 (Challenge)
     * @param ch Challenge structure (fixed fields)
     * @param challengeData Challenge data (4-64 bytes)
     * @return Complete object with header (group/var/qual/len + data)
     */
    static std::vector<uint8_t> BuildChallenge(const Group120Var1& ch,
                                                const std::vector<uint8_t>& challengeData);

    /**
     * @brief Build g120v2 (Reply)
     * @param reply Reply structure
     * @param macValue MAC value
     * @return Complete object with header
     */
    static std::vector<uint8_t> BuildAuthReply(const Group120Var2& reply,
                                                const std::vector<uint8_t>& macValue);

    /**
     * @brief Build g120v3 (Aggressive Mode Request)
     * @param aggr Aggressive mode request structure
     * @return Complete object with header
     */
    static std::vector<uint8_t> BuildAggressiveModeReq(const Group120Var3& aggr);

    /**
     * @brief Build g120v4 (Key Status Request)
     * @param ksr Key status request structure
     * @return Complete object with header
     */
    static std::vector<uint8_t> BuildKeyStatusRequest(const Group120Var4& ksr);

    /**
     * @brief Build g120v5 (Key Status)
     * @param ks Key status structure
     * @param challengeData Optional challenge data
     * @return Complete object with header
     */
    static std::vector<uint8_t> BuildKeyStatus(const Group120Var5& ks,
                                                const std::vector<uint8_t>& challengeData);

    /**
     * @brief Build g120v6 (Key Change)
     * @param kc Key change structure
     * @param wrappedKeyData Encrypted session keys
     * @return Complete object with header
     */
    static std::vector<uint8_t> BuildKeyChange(const Group120Var6& kc,
                                                const std::vector<uint8_t>& wrappedKeyData);

    /**
     * @brief Build g120v7 (Auth Error)
     * @param err Error structure
     * @param errorText Optional error text (UTF-8)
     * @return Complete object with header
     */
    static std::vector<uint8_t> BuildAuthError(const Group120Var7& err,
                                                const std::vector<uint8_t>& errorText);

    /**
     * @brief Build g120v9 (HMAC)
     * @param macValue MAC value for aggressive mode
     * @return Complete object with header
     */
    static std::vector<uint8_t> BuildHMAC(const std::vector<uint8_t>& macValue);

    /**
     * @brief Build complete AUTH_RESPONSE APDU
     * @param fc Function code (AUTH_RESPONSE = 0x83)
     * @param objects Concatenated Group 120 objects
     * @return Complete APDU: FC(1) + IIN(2) + objects
     */
    static std::vector<uint8_t> BuildAuthResponse(FunctionCode fc,
                                                   const std::vector<uint8_t>& objects);

private:
    // DNP3 qualifier for variable-length objects
    static constexpr uint8_t QUAL_VAR_LENGTH = 0x5B;

    // Helper: write little-endian uint16_t
    static inline void WriteUInt16LE(std::vector<uint8_t>& buf, uint16_t value)
    {
        buf.push_back(static_cast<uint8_t>(value & 0xFF));
        buf.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    }

    // Helper: write little-endian uint32_t
    static inline void WriteUInt32LE(std::vector<uint8_t>& buf, uint32_t value)
    {
        buf.push_back(static_cast<uint8_t>(value & 0xFF));
        buf.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    }

    // Helper: build object header (group/var/qual/len)
    static void BuildObjectHeader(std::vector<uint8_t>& buf,
                                   uint8_t group,
                                   uint8_t variation,
                                   uint16_t length);
};

} // namespace opendnp3

#endif // OPENDNP3_GROUP120BUILDER_H
