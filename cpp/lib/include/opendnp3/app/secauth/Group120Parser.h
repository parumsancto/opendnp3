/*
 * Copyright (c) 2026 parumsancto/opendnp3
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * DNP3 Secure Authentication Group 120 Parser
 * Validates and extracts Group 120 object structures from raw DNP3 payloads
 */

#ifndef OPENDNP3_GROUP120PARSER_H
#define OPENDNP3_GROUP120PARSER_H

#include "opendnp3/app/secauth/Group120.h"
#include <cstdint>
#include <cstring>
#include <vector>

namespace opendnp3
{

/**
 * @brief Parser for DNP3 Secure Authentication Group 120 objects
 * @details All methods perform bounds checking and return false on malformed input
 */
class Group120Parser
{
public:
    /**
     * @brief Parse g120v1 (Challenge)
     * @param data Raw object data (after object header)
     * @param len Data length in bytes
     * @param out Output structure (variable ChallengeData stored in vector)
     * @param challengeData Output vector for challenge data (4-64 bytes)
     * @return true if valid, false if malformed
     */
    static bool ParseChallenge(const uint8_t* data, size_t len, 
                               Group120Var1& out, 
                               std::vector<uint8_t>& challengeData);

    /**
     * @brief Parse g120v2 (Reply)
     * @param data Raw object data
     * @param len Data length
     * @param out Output structure
     * @param macValue Output vector for MAC value
     * @return true if valid
     */
    static bool ParseReply(const uint8_t* data, size_t len,
                          Group120Var2& out,
                          std::vector<uint8_t>& macValue);

    /**
     * @brief Parse g120v3 (Aggressive Mode Request)
     * @param data Raw object data
     * @param len Data length
     * @param out Output structure
     * @return true if valid
     */
    static bool ParseAggressiveModeReq(const uint8_t* data, size_t len,
                                       Group120Var3& out);

    /**
     * @brief Parse g120v4 (Session Key Status Request)
     * @param data Raw object data
     * @param len Data length
     * @param out Output structure
     * @return true if valid
     */
    static bool ParseKeyStatusRequest(const uint8_t* data, size_t len,
                                      Group120Var4& out);

    /**
     * @brief Parse g120v5 (Key Status)
     * @param data Raw object data
     * @param len Data length
     * @param out Output structure
     * @param challengeData Output vector for challenge data
     * @return true if valid
     */
    static bool ParseKeyStatus(const uint8_t* data, size_t len,
                               Group120Var5& out,
                               std::vector<uint8_t>& challengeData);

    /**
     * @brief Parse g120v6 (Key Change)
     * @param data Raw object data
     * @param len Data length
     * @param out Output structure
     * @param wrappedKeyData Output vector for encrypted key data
     * @return true if valid
     */
    static bool ParseKeyChange(const uint8_t* data, size_t len,
                               Group120Var6& out,
                               std::vector<uint8_t>& wrappedKeyData);

    /**
     * @brief Parse g120v7 (Auth Error)
     * @param data Raw object data
     * @param len Data length
     * @param out Output structure
     * @param errorText Output vector for error text (UTF-8)
     * @return true if valid
     */
    static bool ParseAuthError(const uint8_t* data, size_t len,
                               Group120Var7& out,
                               std::vector<uint8_t>& errorText);

    /**
     * @brief Parse g120v9 (HMAC)
     * @param data Raw object data
     * @param len Data length
     * @param macValue Output vector for MAC value
     * @return true if valid
     */
    static bool ParseHMAC(const uint8_t* data, size_t len,
                         std::vector<uint8_t>& macValue);

    /**
     * @brief Dispatch parser based on group/variation
     * @param data Complete APDU object data (including group/var/qualifier)
     * @param len Total data length
     * @param groupOut Detected group number
     * @param variationOut Detected variation number
     * @return true if recognized Group 120 object
     */
    static bool Dispatch(const uint8_t* data, size_t len,
                        uint8_t& groupOut, uint8_t& variationOut);

private:
    // Helper: read little-endian uint16_t
    static inline uint16_t ReadUInt16LE(const uint8_t* data)
    {
        return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
    }

    // Helper: read little-endian uint32_t
    static inline uint32_t ReadUInt32LE(const uint8_t* data)
    {
        return static_cast<uint32_t>(data[0]) 
             | (static_cast<uint32_t>(data[1]) << 8)
             | (static_cast<uint32_t>(data[2]) << 16)
             | (static_cast<uint32_t>(data[3]) << 24);
    }
};

} // namespace opendnp3

#endif // OPENDNP3_GROUP120PARSER_H
