/*
 * Copyright (c) 2026 parumsancto/opendnp3
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * DNP3 Secure Authentication v5 Object Structures
 * Per IEEE Std 1815-2012, Section 7 and Appendix A.45
 */

#ifndef OPENDNP3_GROUP120_H
#define OPENDNP3_GROUP120_H

#include <cstdint>

namespace opendnp3
{

// ============================================================================
// ENUMERATIONS (IEEE 1815-2012 Table A-9, Clause 7)
// ============================================================================

/**
 * @brief MAC Algorithm codes for authentication
 * @details IEEE 1815-2012 MAC Algorithm codes (page 729)
 */
// 
enum class MACAlgorithm : uint8_t
{
    NO_MAC               = 0,
    HMAC_SHA1_TRUNC_4    = 1,
    HMAC_SHA1_TRUNC_10   = 2,
    HMAC_SHA256_TRUNC_8  = 3,
    HMAC_SHA256_TRUNC_16 = 4,
    HMAC_SHA1_TRUNC_8    = 5,
    AES_GMAC             = 6
};

/**
 * @brief Key status codes per IEEE 1815-2012 Table 7-8
 */
enum class KeyStatus : uint8_t
{
    OK               = 1,  ///< Session keys valid, no communication failures
    NOT_INIT         = 2,  ///< Keys not initialized
    COMM_FAIL        = 3,  ///< Communication failure since last key change
    AUTH_FAIL        = 4   ///< Authentication failure detected
};

/**
 * @brief Key wrap algorithms per IEEE 1815-2012 Table 7-9
 */
enum class KeyWrapAlgorithm : uint8_t
{
    AES128 = 1,  ///< AES-128 Key Wrap (RFC 3394)
    AES256 = 2   ///< AES-256 Key Wrap (RFC 3394)
};

/**
 * @brief Challenge reason codes per IEEE 1815-2012 Table 7-5
 */
enum class ChallengeReason : uint8_t
{
    NOT_USED        = 0,
    CRITICAL        = 1, // IEEE 1815-2012 Table A-2: challenge for critical function
    AGGRESSIVE_MODE = 2  // challenge for aggressive mode
};

/**
 * @brief Error codes for g120v7 (Auth Error)
 * @details IEEE 1815-2012 Table 7-17
 */
enum class AuthErrorCode : uint8_t
{
    AUTHENTICATION_FAILED    = 1,  ///< MAC verification failed
    UNEXPECTED_REPLY         = 2,  ///< Reply without pending challenge
    NO_USER                  = 3,  ///< User number not configured
    UNAUTHORIZED_OPERATION   = 4,  ///< User lacks permission for operation
    INVALID_SIGNATURE        = 5,  ///< Digital signature invalid
    INVALID_CERTIFICATION    = 6,  ///< Certificate validation failed
    UNKNOWN_USER             = 7,  ///< User not in authority database
    MAX_SESSION_KEY_REACHED  = 8,  ///< Session key limit exceeded
    PERMISSION_DENIED        = 9   ///< Role-based access control violation
};

/**
 * @brief Key change method codes (g120v8, g120v10, g120v11)
 * @details IEEE 1815-2012 Section 7.6
 */
enum class KeyChangeMethod : uint8_t
{
    // Symmetric (0-63)
    AES128_KEY_WRAP = 1,  ///< Symmetric Update Key encrypted with Authority Certification Key
    AES256_KEY_WRAP = 2,

    // Asymmetric (64-127)
    RSA_1024        = 65,  ///< 1024-bit RSA with SHA-1 (deprecated)
    RSA_2048_SHA256 = 66,  ///< 2048-bit RSA with SHA-256
    RSA_3072_SHA256 = 67,  ///< 3072-bit RSA with SHA-256

    // 128-255: Vendor-specific (not interoperable)
};

// ============================================================================
// PACKED STRUCTURES - All Group 120 variations
// IEEE 1815-2012 Appendix A.45
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief g120v1 - Challenge (IEEE 1815-2012 Table A-45.1)
 * @details Sent by challenger to request authentication
 * Challenge Data length: 4-64 bytes (variable)
 */
struct Group120Var1
{
    uint32_t csq;            ///< Challenge Sequence Number
    uint16_t userNumber;     ///< User Number being challenged
    uint8_t  macAlgorithm;   ///< MAC algorithm (MACAlgorithm enum)
    uint8_t  reason;         ///< Reason for challenge (ChallengeReason enum)
    // Variable-length ChallengeData follows (4-64 octets)
};

/**
 * @brief g120v2 - Reply (IEEE 1815-2012 Table A-45.2)
 * @details Response to challenge with MAC value
 * MAC Value length: variable (depends on MAC algorithm)
 */
struct Group120Var2
{
    uint32_t csq;            ///< Challenge Sequence Number (echoed)
    uint16_t userNumber;     ///< User Number (echoed)
    // Variable-length MACValue follows
};

/**
 * @brief g120v3 - Aggressive Mode Request (IEEE 1815-2012 Table A-45.3)
 * @details Pre-emptive authentication without waiting for challenge
 */
struct Group120Var3
{
    uint32_t csq;            ///< Challenge Sequence Number (from last challenge)
    uint16_t userNumber;     ///< User Number making request
};

/**
 * @brief g120v4 - Session Key Status Request (IEEE 1815-2012 Table A-45.4)
 * @details Master requests session key status from outstation
 */
struct Group120Var4
{
    uint16_t userNumber;     ///< User Number to query
};

/**
 * @brief g120v5 - Key Status (IEEE 1815-2012 Table A-45.5)
 * @details Outstation reports session key status
 * Challenge Data length: variable
 */
struct Group120Var5
{
    uint32_t ksq;            ///< Key Change Sequence Number
    uint16_t userNumber;     ///< User Number
    uint8_t  keyWrapAlgo;    ///< Key wrap algorithm (KeyWrapAlgorithm enum)
    uint8_t  status;         ///< Key status (KeyStatus enum)
    uint8_t macAlgorithm;    ///< MAC algorithm: 0 = no MAC (when NOT_INIT)  ← ДОДАТИ
    // Wire format continued: UINT16 ChallengeDataLength + Challenge Data + MAC Value
};

/**
 * @brief g120v6 - Key Change (IEEE 1815-2012 Table A-45.6)
 * @details Master sends new session keys to outstation
 * Wrapped Key Data length: variable
 */
struct Group120Var6
{
    uint32_t ksq;            ///< Key Change Sequence Number (from g120v5)
    uint16_t userNumber;     ///< User Number
    // Variable-length WrappedKeyData follows (encrypted session keys)
};

/**
 * @brief g120v7 - Error (IEEE 1815-2012 Table A-45.7)
 * @details Authentication error report
 * Error Text length: variable
 */
struct Group120Var7
{
    uint32_t csq;            ///< Challenge Sequence Number at time of error
    uint16_t userNumber;     ///< User Number associated with error
    uint16_t assocId;        ///< Association ID (master/outstation identifier)
    uint8_t  errorCode;      ///< Error code (AuthErrorCode enum)
    uint8_t  timeOfError[6]; ///< DNP3TIME (48-bit timestamp, ms since epoch)
    // Variable-length ErrorText follows (UTF-8, optional)
};

/**
 * @brief g120v8 - User Certificate (IEEE 1815-2012 Table A-45.8)
 * @details User's X.509 certificate for asymmetric authentication
 * Certificate Data length: variable
 */
struct Group120Var8
{
    uint8_t keyChangeMethod; ///< Key change method (KeyChangeMethod enum)
    // Variable-length CertificateData follows (X.509 DER encoding)
};

/**
 * @brief g120v9 - HMAC (IEEE 1815-2012 Table A-45.9)
 * @details Message authentication code for aggressive mode
 * MAC Value length: variable (depends on algorithm)
 */
struct Group120Var9
{
    // Variable-length MACValue follows
    // NOTE: This object has NO fixed-length header - MAC value starts at offset 0
};

/**
 * @brief g120v10 - User Status Change (IEEE 1815-2012 Table A-45.10)
 * @details Authority notifies outstation of user credential changes
 * Variable fields: UserName, UserPublicKey, CertificationData
 */
struct Group120Var10
{
    uint8_t  keyChangeMethod;  ///< Key change method (KeyChangeMethod enum)
    uint16_t userRole;         ///< User role bitmap (IEEE 1815-2012 Table 7-13)
    uint16_t userRoleExpiry;   ///< Days until role expires (0 = no expiry)
    // Variable fields follow in order:
    // - UserNameLength (uint16_t) + UserName (UTF-8 string)
    // - UserPublicKeyLength (uint16_t) + UserPublicKey (if asymmetric)
    // - CertificationDataLength (uint16_t) + CertificationData
};

/**
 * @brief g120v11 - Update Key Change Request (IEEE 1815-2012 Table A-45.11)
 * @details Master initiates Update Key change procedure
 * Challenge Data length: variable
 */
struct Group120Var11
{
    uint32_t ksq;            ///< Key Change Sequence Number
    uint16_t userNumber;     ///< User Number
    // Variable fields follow:
    // - KeyChangeMethod (uint8_t)
    // - UserNameLength (uint16_t) + UserName
    // - MasterChallengeDataLength (uint16_t) + MasterChallengeData
};

/**
 * @brief g120v12 - Update Key Change Reply (IEEE 1815-2012 Table A-45.12)
 * @details Outstation responds to Update Key change request
 * Challenge Data length: variable
 */
struct Group120Var12
{
    uint32_t ksq;            ///< Key Change Sequence Number (assigned by outstation)
    uint16_t userNumber;     ///< User Number (assigned by outstation)
    // Variable fields follow:
    // - OutstationChallengeDataLength (uint16_t)
    // - OutstationChallengeData (pseudo-random)
};

/**
 * @brief g120v13 - Update Key Change (IEEE 1815-2012 Table A-45.13)
 * @details Master sends encrypted new Update Key to outstation
 * Encrypted Update Key length: variable
 */
struct Group120Var13
{
    uint32_t ksq;            ///< Key Change Sequence Number (from g120v12)
    uint16_t userNumber;     ///< User Number (from g120v12)
    // Variable fields follow:
    // - EncryptedUpdateKeyLength (uint16_t)
    // - EncryptedUpdateKey (includes: UserName + UpdateKey + OutstationChallenge + padding)
};

/**
 * @brief g120v14 - Update Key Change Confirmation (IEEE 1815-2012 Table A-45.14)
 * @details Confirms successful Update Key change
 * MAC Value length: variable
 */
struct Group120Var14
{
    // Variable-length MACValue follows (calculated using new Update Key)
    // NOTE: This object has NO fixed-length header - MAC value starts at offset 0
};

/**
 * @brief g120v15 - Session Key Status Request (IEEE 1815-2012 Table A-45.15)
 * @details Master requests session key status (alternative to g120v4)
 */
struct Group120Var15
{
    uint16_t userNumber;     ///< User Number to query
};

#pragma pack(pop)

// ============================================================================
// CONSTANTS
// ============================================================================

/// Minimum challenge data length (IEEE 1815-2012 Section 7.5.2.2)
constexpr uint16_t MIN_CHALLENGE_DATA_LENGTH = 4;

/// Maximum challenge data length (IEEE 1815-2012 Section 7.5.2.2)
constexpr uint16_t MAX_CHALLENGE_DATA_LENGTH = 64;

/// Default User Number for master station (IEEE 1815-2012 Section 7.2.3)
constexpr uint16_t DEFAULT_MASTER_USER = 1;

/// DNP3TIME epoch: 00:00:00 UTC on January 1, 1970
constexpr uint64_t DNP3_EPOCH_MS = 0;

} // namespace opendnp3

#endif // OPENDNP3_GROUP120_H
