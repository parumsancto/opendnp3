/*
 * Copyright (c) 2026 parumsancto/opendnp3
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * DNP3 Secure Authentication v5 Key Manager
 * Implements Session Key Change protocol per IEEE 1815-2012 Section 7.5.5
 */

#ifndef OPENDNP3_SAKEYMANAGER_H
#define OPENDNP3_SAKEYMANAGER_H

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
 * @brief Secure Authentication v5 Session Key Manager
 * @details Implements key change protocol per IEEE 1815-2012 Figure 7-3
 * 
 * Key Hierarchy:
 * - Update Key (32 bytes): Pre-shared or remotely changed, used to encrypt session keys
 * - Session Keys (2 x 16 bytes): Control direction + Monitor direction, changed frequently
 * 
 * Protocol Flow (Outstation side):
 * 1. Master → g120v4 Key Status Request
 * 2. Outstation → g120v5 Key Status (includes KSQ, status, challenge data)
 * 3. Master → g120v6 Key Change (wrapped session keys)
 * 4. Outstation decrypts, validates, updates keys
 */
class SAKeyManager
{
public:
    /**
     * @brief Construct Key Manager with Update Key
     * @details IEEE 1815-2012 Section 7.5.5.3
     * 
     * Update Key is pre-shared (manually configured) or remotely changed
     * via asymmetric/symmetric methods (g120v10-v14, not implemented here)
     * 
     * @param updateKey 32-byte Update Key (AES-256 key wrap key)
     */
    explicit SAKeyManager(const std::array<uint8_t, 32>& updateKey, SAMode mode = SAMode::SAV5);

    ~SAKeyManager();

    // ========================================================================
    // OUTSTATION SIDE - Session Key Change Protocol
    // ========================================================================

    uint16_t GetSessionKeyLen() const { return sessionKeyLen; }
    /**
     * @brief Handle g120v4 Key Status Request from master
     * @details IEEE 1815-2012 Section 7.5.5.2 (Step 1 of Figure 7-3)
     * 
     * Process:
     * 1. Increment KSQ (Key Change Sequence Number)
     * 2. Generate 16 random bytes for challenge data
     * 3. Get current key status for user (OK, NOT_INIT, COMM_FAIL, AUTH_FAIL)
     * 4. Build g120v5 Key Status response
     * 
     * @param userNum User number requesting status
     * @return Complete g120v5 Key Status bytes (with object header)
     */
    std::vector<uint8_t> OnKeyStatusRequest(uint16_t userNum);
    
    std::vector<uint8_t> OnKeyStatusRequestWithMAC(
        uint16_t userNum,
        const std::array<uint8_t, 32>& monitorKey,
        MACAlgorithm macAlgo
    );

    /**
     * @brief Handle g120v6 Key Change from master
     * @details IEEE 1815-2012 Section 7.5.5.3 (Step 2 of Figure 7-3)
     * @param keyChange Parsed g120v6 structure
     * @param wrappedKeyData Encrypted session keys (40 bytes)
     * @param keyChangeAlFragment the entire Application Layer bytes of the received g120v6
     * @param userNumOut Output: user number for these keys
     * @param controlKeyOut Output: decrypted control direction key (padded to 32 bytes)
     * @param monitorKeyOut Output: decrypted monitor direction key (padded to 32 bytes)
     * @return true if unwrap successful and KSQ valid
     */
    bool OnKeyChange(const Group120Var6& keyChange,
                     const std::vector<uint8_t>& wrappedKeyData,
                     const std::vector<uint8_t>& keyChangeAlFragment,
                     uint16_t& userNumOut,
                     std::array<uint8_t, 32>& controlKeyOut,
                     std::array<uint8_t, 32>& monitorKeyOut);
    
    /**
     * @brief Build Key Status Confirmation after successful Key Change
     * @details IEEE 1815-2012 Section 7.5.5.3.3 step 7
     * Sends g120v5 with Status=OK, same KSQ (no increment), and HMAC using monitorKey.
     * MAC input = full AL fragment of the received g120v6 (SAv2: SHA-1, SAv5: SHA-256).
     * @param userNum   User number
     * @param monitorKey Monitor Direction Session Key (from OnKeyChange output)
     * @param macAlgo   MAC algorithm value (e.g. HMAC_SHA1_TRUNC_10 for SAv2)
     */
    std::vector<uint8_t> BuildKeyStatusConfirmation(
        uint16_t userNum,
        const std::array<uint8_t, 32>& monitorKey,
        MACAlgorithm macAlgo = MACAlgorithm::HMAC_SHA256_TRUNC_16);

    /**
     * @brief Get current Key Change Sequence Number
     * @return Current KSQ value
     */
    uint32_t GetKSQ() const;

    /**
     * @brief Get current key status for a user
     * @param userNum User number
     * @return Key status (OK, NOT_INIT, COMM_FAIL, AUTH_FAIL)
     */
    KeyStatus GetKeyStatus(uint16_t userNum) const;

    /**
     * @brief Mark user's keys as invalid due to error
     * @details Called on authentication failure, timeout, or comm loss
     * @param userNum User number
     * @param status New status (COMM_FAIL, AUTH_FAIL, etc.)
     */
    void InvalidateKeys(uint16_t userNum, KeyStatus status);

    /**
     * @brief Set key wrap algorithm
     * @details IEEE 1815-2012 Section 7.5.5.2.3.3
     * @param algo AES128 or AES256 (default: AES128)
     */
    void SetKeyWrapAlgorithm(KeyWrapAlgorithm algo);

    /**
     * @brief Get current key wrap algorithm
     */
    KeyWrapAlgorithm GetKeyWrapAlgorithm() const;

    /**
     * @brief Set callback for logging security events
     */
    using LogCallback = std::function<void(const char* severity, const std::string& message)>;
    void SetLogCallback(LogCallback callback);

private:
    /// SA mode (SAV2 or SAV5)
    SAMode mode_;

    /// Update Key (32 bytes; SAv2 uses only first 16)
    std::array<uint8_t, 32> updateKey;
    uint16_t sessionKeyLen = 16;

    /// Key Change Sequence Number (increments on each key status request)
    /// IEEE 1815-2012 Section 7.5.5.3.3
    uint32_t ksq;

    /// Key wrap algorithm (AES128 or AES256)
    KeyWrapAlgorithm keyWrapAlgo;

    /// Per-user key status (OK, NOT_INIT, COMM_FAIL, AUTH_FAIL)
    std::map<uint16_t, KeyStatus> keyStatusMap;

    /// Last generated challenge data (16 bytes, stored for verification)
    std::vector<uint8_t> lastChallengeData;

    /// User number from last key status request
    uint16_t lastUserNum;

    /// Logging callback
    LogCallback logCallback_;

    /**
     * @brief AES-256 Key Unwrap per RFC 3394
     * @details Uses OpenSSL AES_unwrap_key()
     * 
     * Input: 40 bytes wrapped data
     * - 8 bytes IV (integrity check value)
     * - 32 bytes encrypted payload
     * 
     * Output: 32 bytes unwrapped data
     * - 16 bytes Control Key
     * - 16 bytes Monitor Key
     * 
     * @param wrappedData 40-byte encrypted session keys
     * @return 32-byte unwrapped keys [Control(16) | Monitor(16)], or empty on failure
     */
    std::vector<uint8_t> AESKeyUnwrap(const std::vector<uint8_t>& wrappedData);

    /**
     * @brief Generate cryptographically random challenge data
     * @return 16 random bytes
     */
    std::vector<uint8_t> GenerateRandomChallengeData();

    /**
     * @brief Log security event
     */
    void Log(const char* severity, const std::string& message);

    // OpenSSL context (opaque)
    struct OpenSSLContext;
    OpenSSLContext* sslCtx_;
    // Entire AL fragment of received g120v6, used as MAC input in BuildKeyStatusConfirmation.
    // Both SAv2 and SAv5 compute the confirmation MAC over the full AL fragment.
    std::vector<uint8_t> lastKeyChangeAlFragment;
};

} // namespace opendnp3

#endif // OPENDNP3_SAKEYMANAGER_H
