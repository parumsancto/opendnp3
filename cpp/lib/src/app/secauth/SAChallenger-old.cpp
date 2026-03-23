/*
 * Copyright (c) 2026 parumsancto/opendnp3
 */

#include "opendnp3/app/secauth/SAChallenger.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace opendnp3
{

struct SAChallenger::OpenSSLContext
{
    // Placeholder for future state if needed
};

SAChallenger::SAChallenger()
    : csq_(0),
      lastAlgo_(MACAlgorithm::HMAC_SHA256_TRUNC_16),
      lastUserNum_(0),
      lastReason_(ChallengeReason::CRITICAL),
      sslCtx_(new OpenSSLContext())
{
}

SAChallenger::~SAChallenger()
{
    delete sslCtx_;
}

void SAChallenger::SetLogCallback(LogCallback callback)
{
    logCallback_ = callback;
}

void SAChallenger::Log(const char* severity, const std::string& message)
{
    if (logCallback_)
    {
        logCallback_(severity, message);
    }
}

bool SAChallenger::IsCriticalFunction(uint8_t functionCode)
{
    // IEEE 1815-2012 Table 7-7: Mandatory Critical Functions
    switch (functionCode)
    {
    // Control operations (always critical)
    case 0x02:  // WRITE
    case 0x03:  // SELECT
    case 0x04:  // OPERATE
    case 0x05:  // DIRECT_OPERATE
    case 0x06:  // DIRECT_OPERATE_NO_ACK
        return true;

    // Freeze operations (always critical)
    case 0x07:  // IMMEDIATE_FREEZE
    case 0x08:  // IMMEDIATE_FREEZE_NO_ACK
    case 0x09:  // FREEZE_CLEAR
    case 0x0A:  // FREEZE_CLEAR_NO_ACK
    case 0x0B:  // FREEZE_AT_TIME
    case 0x0C:  // FREEZE_AT_TIME_NO_ACK
        return true;

    // System operations (always critical)
    case 0x0D:  // COLD_RESTART
    case 0x0E:  // WARM_RESTART
        return true;

    // Configuration operations (always critical)
    case 0x14:  // ENABLE_UNSOLICITED
    case 0x15:  // DISABLE_UNSOLICITED
    case 0x16:  // ASSIGN_CLASS
        return true;

    // Time operations (critical per Table 7-7)
    case 0x17:  // DELAY_MEASURE
        return true;

    // Optional critical functions (commented out - configurable in production)
    // case 0x01:  // READ (may be critical for sensitive data)
    // case 0x18:  // RECORD_CURRENT_TIME
    //     return true;

    default:
        return false;
    }
}

std::vector<uint8_t> SAChallenger::GenerateRandomChallengeData()
{
    // IEEE 1815-2012 Section 7.5.2.2: Challenge data 4-64 bytes
    // Using 16 bytes for optimal security/bandwidth tradeoff
    constexpr size_t CHALLENGE_LEN = 16;
    
    std::vector<uint8_t> challengeData(CHALLENGE_LEN);

    // FIPS 186-2 requirement: cryptographically secure random number generator
    if (RAND_bytes(challengeData.data(), CHALLENGE_LEN) != 1)
    {
        Log("ERROR", "RAND_bytes failed - using fallback (INSECURE)");
        // Fallback: fill with timestamp-based pseudo-random (NOT SECURE)
        for (size_t i = 0; i < CHALLENGE_LEN; ++i)
        {
            challengeData[i] = static_cast<uint8_t>(rand() & 0xFF);
        }
    }

    return challengeData;
}

std::vector<uint8_t> SAChallenger::GenerateChallenge(uint16_t userNum,
                                                      MACAlgorithm algo,
                                                      ChallengeReason reason)
{
    // IEEE 1815-2012 Section 7.5.2.3.3 rule (g):
    // CSQ is independent of user number and increments on each challenge
    ++csq_;

    // Generate cryptographically random challenge data
    lastChallengeData_ = GenerateRandomChallengeData();
    lastAlgo_ = algo;
    lastUserNum_ = userNum;
    lastReason_ = reason;

    // Build g120v1 Challenge
    Group120Var1 challenge;
    challenge.csq = csq_;
    challenge.userNumber = userNum;
    challenge.macAlgorithm = static_cast<uint8_t>(algo);
    challenge.reason = static_cast<uint8_t>(reason);

    std::vector<uint8_t> challengeBytes = Group120Builder::BuildChallenge(
        challenge, lastChallengeData_);

    std::ostringstream oss;
    oss << "Challenge generated: CSQ=" << csq_ 
        << ", User=" << userNum
        << ", Algo=" << static_cast<int>(algo)
        << ", Reason=" << static_cast<int>(reason);
    Log("INFO", oss.str());

    return challengeBytes;
}

std::vector<uint8_t> SAChallenger::BuildAuthData(uint32_t csq,
                                                  uint16_t userNum,
                                                  MACAlgorithm algo,
                                                  ChallengeReason reason,
                                                  const std::vector<uint8_t>& challengeData,
                                                  const std::vector<uint8_t>& originalAPDU)
{
    std::vector<uint8_t> authData;

    // IEEE 1815-2012 Figure 7-4:
    // authentication_data = challenge_header || original_ASDU || challenge_data

    // Challenge header (8 bytes)
    authData.push_back(csq & 0xFF);
    authData.push_back((csq >> 8) & 0xFF);
    authData.push_back((csq >> 16) & 0xFF);
    authData.push_back((csq >> 24) & 0xFF);
    authData.push_back(userNum & 0xFF);
    authData.push_back((userNum >> 8) & 0xFF);
    authData.push_back(static_cast<uint8_t>(algo));
    authData.push_back(static_cast<uint8_t>(reason));

    // Original ASDU
    authData.insert(authData.end(), originalAPDU.begin(), originalAPDU.end());

    // Challenge data
    authData.insert(authData.end(), challengeData.begin(), challengeData.end());

    return authData;
}

std::vector<uint8_t> SAChallenger::CalculateMAC(MACAlgorithm algo,
                                                 const std::array<uint8_t, 32>& key,
                                                 const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> mac;

    switch (algo)
    {
    case MACAlgorithm::HMAC_SHA256_TRUNC_16:
    {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digestLen = 0;

        HMAC(EVP_sha256(),
             key.data(), 32,
             data.data(), data.size(),
             digest, &digestLen);

        if (digestLen >= 16)
        {
            mac.assign(digest, digest + 16);
        }
        break;
    }

    case MACAlgorithm::HMAC_SHA1_TRUNC_10:
    {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digestLen = 0;

        HMAC(EVP_sha1(),
             key.data(), 20,
             data.data(), data.size(),
             digest, &digestLen);

        if (digestLen >= 10)
        {
            mac.assign(digest, digest + 10);
        }
        break;
    }

    case MACAlgorithm::HMAC_SHA256_TRUNC_8:
    {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digestLen = 0;

        HMAC(EVP_sha256(),
             key.data(), 32,
             data.data(), data.size(),
             digest, &digestLen);

        if (digestLen >= 8)
        {
            mac.assign(digest, digest + 8);
        }
        break;
    }

    case MACAlgorithm::AES_GMAC:
    {
        if (data.size() < 12)
        {
            Log("ERROR", "AES-GMAC requires at least 12 bytes for nonce");
            break;
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            break;

        unsigned char tag[16];
        int len = 0;

        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            break;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            break;
        }

        const unsigned char* nonce = data.data();
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            break;
        }

        if (EVP_EncryptUpdate(ctx, nullptr, &len, data.data(), static_cast<int>(data.size())) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            break;
        }

        if (EVP_EncryptFinal_ex(ctx, nullptr, &len) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            break;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            break;
        }

        mac.assign(tag, tag + 16);
        EVP_CIPHER_CTX_free(ctx);
        break;
    }

    default:
        Log("ERROR", "Unsupported MAC algorithm");
        break;
    }

    return mac;
}

bool SAChallenger::ConstantTimeCompare(const std::vector<uint8_t>& mac1,
                                       const std::vector<uint8_t>& mac2)
{
    if (mac1.size() != mac2.size())
        return false;

    // Constant-time comparison to prevent timing attacks
    unsigned char result = 0;
    for (size_t i = 0; i < mac1.size(); ++i)
    {
        result |= mac1[i] ^ mac2[i];
    }

    return (result == 0);
}

bool SAChallenger::ValidateReply(const Group120Var2& reply,
                                 const std::vector<uint8_t>& macValue,
                                 const std::vector<uint8_t>& originalAPDU,
                                 const std::array<uint8_t, 32>& sessionKey)
{
    // Step 1: Verify CSQ matches last sent challenge
    if (reply.csq != csq_)
    {
        std::ostringstream oss;
        oss << "Reply CSQ mismatch: expected " << csq_ 
            << ", received " << reply.csq;
        Log("ERROR", oss.str());
        return false;
    }

    // Step 2: Verify user number matches
    if (reply.userNumber != lastUserNum_)
    {
        std::ostringstream oss;
        oss << "Reply user mismatch: expected " << lastUserNum_
            << ", received " << reply.userNumber;
        Log("ERROR", oss.str());
        return false;
    }

    // Step 3: Build authentication data
    std::vector<uint8_t> authData = BuildAuthData(
        csq_, lastUserNum_, lastAlgo_, lastReason_,
        lastChallengeData_, originalAPDU);

    // Step 4: Calculate expected MAC
    std::vector<uint8_t> expectedMAC = CalculateMAC(lastAlgo_, sessionKey, authData);

    if (expectedMAC.empty())
    {
        Log("ERROR", "MAC calculation failed during validation");
        return false;
    }

    // Step 5: Constant-time comparison
    bool valid = ConstantTimeCompare(expectedMAC, macValue);

    if (valid)
    {
        std::ostringstream oss;
        oss << "Reply validated: CSQ=" << reply.csq 
            << ", User=" << reply.userNumber;
        Log("INFO", oss.str());
    }
    else
    {
        std::ostringstream oss;
        oss << "Reply MAC invalid: CSQ=" << reply.csq
            << ", User=" << reply.userNumber;
        Log("ERROR", oss.str());
    }

    return valid;
}

bool SAChallenger::ValidateAggressiveMode(const Group120Var3& aggrReq,
                                          const std::vector<uint8_t>& macValue,
                                          const std::vector<uint8_t>& apdu,
                                          const std::array<uint8_t, 32>& sessionKey)
{
    // IEEE 1815-2012 Section 7.5.4: Aggressive Mode
    // CSQ in g120v3 should reference last sent challenge

    if (aggrReq.csq != csq_)
    {
        std::ostringstream oss;
        oss << "Aggressive mode CSQ mismatch: expected " << csq_
            << ", received " << aggrReq.csq;
        Log("WARN", oss.str());
        return false;
    }

    if (aggrReq.userNumber != lastUserNum_)
    {
        std::ostringstream oss;
        oss << "Aggressive mode user mismatch: expected " << lastUserNum_
            << ", received " << aggrReq.userNumber;
        Log("WARN", oss.str());
        return false;
    }

    // Build authentication data using last challenge parameters
    std::vector<uint8_t> authData = BuildAuthData(
        aggrReq.csq, aggrReq.userNumber, lastAlgo_, lastReason_,
        lastChallengeData_, apdu);

    // Calculate expected MAC
    std::vector<uint8_t> expectedMAC = CalculateMAC(lastAlgo_, sessionKey, authData);

    if (expectedMAC.empty())
    {
        Log("ERROR", "MAC calculation failed for aggressive mode");
        return false;
    }

    // Constant-time comparison
    bool valid = ConstantTimeCompare(expectedMAC, macValue);

    if (valid)
    {
        Log("INFO", "Aggressive mode validated");
    }
    else
    {
        Log("ERROR", "Aggressive mode MAC invalid");
    }

    return valid;
}

uint32_t SAChallenger::GetCurrentCSQ() const
{
    return csq_;
}

void SAChallenger::ResetCSQ()
{
    csq_ = 0;
    Log("INFO", "CSQ counter reset");
}

} // namespace opendnp3
