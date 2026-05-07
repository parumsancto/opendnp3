/*
 * Copyright (c) 2026 parumsancto/opendnp3
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * DNP3 Secure Authentication v5 Responder (Outstation side)
 * Implements challenge-response authentication per IEEE 1815-2012 Section 7
 */

#ifndef OPENDNP3_SARESPONDER_H
#define OPENDNP3_SARESPONDER_H

#include "opendnp3/app/secauth/Group120.h"
#include "opendnp3/app/secauth/Group120Builder.h"
#include "opendnp3/app/secauth/SAMode.h"
#include <array>
#include <map>
#include <vector>
#include <cstdint>
#include <functional>

namespace opendnp3
{

/**
 * @brief Secure Authentication v5 Responder State Machine
 * @details Implements outstation-side authentication per IEEE 1815-2012 Table 7-9
 * 
 * Responsibilities:
 * - Respond to challenges from master (g120v1 → g120v2)
 * - Maintain per-user session keys (control direction, monitoring direction)
 * - Calculate MAC values using HMAC-SHA256/SHA1 or AES-GMAC
 * - Track Challenge Sequence Numbers (CSQ) to prevent replay attacks
 */
class SAResponder
{
public:
    explicit SAResponder(SAMode mode = SAMode::SAV5);
    ~SAResponder();

    /**
     * @brief Handle incoming Challenge (g120v1) from master
     * @details IEEE 1815-2012 Section 7.5.2
     * 
     * Process:
     * 1. Validate user number has valid session keys
     * 2. Verify CSQ is unique (not a replay)
     * 3. Build authentication data: challenge_header || original_ASDU || challenge_data
     * 4. Calculate MAC using specified algorithm and control direction key
     * 5. Return g120v2 Reply with CSQ echoed and MAC value
     * 
     * @param challenge Parsed g120v1 structure
     * @param challengeData Variable challenge data (4-64 bytes)
     * @param originalAPDU The critical ASDU being authenticated (full fragment)
     * @return g120v2 Reply bytes (complete object with header), or empty on failure
     */
    std::vector<uint8_t> OnChallenge(const Group120Var1& challenge,
                                      const std::vector<uint8_t>& challengeData,
                                      const std::vector<uint8_t>& originalAPDU);

    /**
     * @brief Handle incoming Auth Error (g120v7) from master
     * @details IEEE 1815-2012 Section 7.5.7
     * 
     * Actions:
     * - Log error for security audit
     * - If AUTHENTICATION_FAILED: may invalidate session keys
     * - Update statistics (security event counters)
     * 
     * @param error Parsed g120v7 structure
     * @param errorText Optional error text (UTF-8)
     */
    void OnAuthError(const Group120Var7& error,
                     const std::vector<uint8_t>& errorText);

    /**
     * @brief Set session keys for a user after successful key change
     * @details IEEE 1815-2012 Section 7.5.5 (g120v6 Key Change)
     * 
     * @param userNum User number (1-65535)
     * @param controlKey Session key for control direction (master → outstation)
     * @param monitorKey Session key for monitoring direction (outstation → master)
     */
    void SetSessionKeys(uint16_t userNum,
                        const std::array<uint8_t, 32>& controlKey,
                        const std::array<uint8_t, 32>& monitorKey);

    /**
     * @brief Check if user has valid session keys
     * @param userNum User number
     * @return true if session keys are initialized and valid
     */
    bool HasValidKeys(uint16_t userNum) const;

    /**
     * @brief Invalidate session keys for a user
     * @details Call after authentication failure or session timeout
     * @param userNum User number
     */
    void InvalidateKeys(uint16_t userNum);

    /**
     * @brief Clear all session state (e.g., on restart)
     */
    void Reset();

    /**
     * @brief Set callback for logging security events
     * @param callback Function(severity, message)
     */
    using LogCallback = std::function<void(const char* severity, const std::string& message)>;
    void SetLogCallback(LogCallback callback);

private:
    /**
     * @brief Per-user session state
     */
    struct UserSession
    {
        std::array<uint8_t, 32> controlKey;   ///< Control direction (master → outstation)
        std::array<uint8_t, 32> monitorKey;   ///< Monitoring direction (outstation → master)
        uint32_t lastCSQ;                     ///< Last received CSQ (for replay detection)
        bool valid;                           ///< Keys initialized and usable

        UserSession() : lastCSQ(0), valid(false)
        {
            controlKey.fill(0);
            monitorKey.fill(0);
        }
    };

    /// SA mode (SAV2 or SAV5)
    SAMode mode_;

    /// Session state per user number
    std::map<uint16_t, UserSession> sessions_;

    /// Logging callback
    LogCallback logCallback_;

    /**
     * @brief Calculate MAC per IEEE 1815-2012 Section 7.2.3.5
     * @details 
     * Input data = challenge_fixed_fields || original_ASDU || challenge_data
     * 
     * Algorithms:
     * - HMAC_SHA256_TRUNC_16: HMAC-SHA256(key, data)[0:16]
     * - HMAC_SHA1_TRUNC_10:   HMAC-SHA1(key, data)[0:10]
     * - AES_GMAC: AES-128-GMAC with nonce=challengeData[0:12]
     * 
     * @param algo MAC algorithm
     * @param key Session key (32 bytes, only first 16/32 used depending on algo)
     * @param data Complete authentication data
     * @return MAC value (truncated per algorithm)
     */
    std::vector<uint8_t> CalculateMAC(MACAlgorithm algo,
                                       const std::array<uint8_t, 32>& key,
                                       const std::vector<uint8_t>& data);

    /**
     * @brief Build authentication data per IEEE 1815-2012 Figure 7-4
     * @details Concatenation: challenge_header || original_ASDU || challenge_data
     * 
     * challenge_header = CSQ(4) || UserNum(2) || MACAlgo(1) || Reason(1)
     * 
     * @param challenge g120v1 structure
     * @param challengeData Variable challenge data
     * @param originalAPDU Critical ASDU being authenticated
     * @return Complete authentication input for MAC calculation
     */
    std::vector<uint8_t> BuildAuthData(const Group120Var1& challenge,
                                         const std::vector<uint8_t>& challengeData,
                                         const std::vector<uint8_t>& originalAPDU);

    /**
     * @brief Log security event
     * @param severity "INFO", "WARN", "ERROR"
     * @param message Event description
     */
    void Log(const char* severity, const std::string& message);

    // OpenSSL context (opaque pointer to avoid exposing OpenSSL headers)
    struct OpenSSLContext;
    OpenSSLContext* sslCtx_;
};

} // namespace opendnp3

#endif // OPENDNP3_SARESPONDER_H
