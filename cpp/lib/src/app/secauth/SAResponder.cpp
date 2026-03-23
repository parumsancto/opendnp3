/*
 * Copyright (c) 2026 parumsancto/opendnp3
 */

#include "opendnp3/app/secauth/SAResponder.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace opendnp3
{

// OpenSSL context (placeholder for future EVP_CIPHER_CTX if needed)
struct SAResponder::OpenSSLContext
{
    // Currently unused - HMAC and GMAC use stateless APIs
};

SAResponder::SAResponder()
    : sslCtx_(new OpenSSLContext())
{
}

SAResponder::~SAResponder()
{
    delete sslCtx_;
}

void SAResponder::SetLogCallback(LogCallback callback)
{
    logCallback_ = callback;
}

void SAResponder::Log(const char* severity, const std::string& message)
{
    if (logCallback_)
    {
        logCallback_(severity, message);
    }
}

void SAResponder::SetSessionKeys(uint16_t userNum,
                                  const std::array<uint8_t, 32>& controlKey,
                                  const std::array<uint8_t, 32>& monitorKey)
{
    UserSession& session = sessions_[userNum];
    session.controlKey = controlKey;
    session.monitorKey = monitorKey;
    session.valid = true;
    session.lastCSQ = 0;  // Reset CSQ tracking on key change

    std::ostringstream oss;
    oss << "Session keys set for user " << userNum;
    Log("INFO", oss.str());
}

bool SAResponder::HasValidKeys(uint16_t userNum) const
{
    auto it = sessions_.find(userNum);
    return (it != sessions_.end() && it->second.valid);
}

void SAResponder::InvalidateKeys(uint16_t userNum)
{
    auto it = sessions_.find(userNum);
    if (it != sessions_.end())
    {
        it->second.valid = false;
        std::ostringstream oss;
        oss << "Session keys invalidated for user " << userNum;
        Log("WARN", oss.str());
    }
}

void SAResponder::Reset()
{
    sessions_.clear();
    Log("INFO", "All session state cleared");
}

std::vector<uint8_t> SAResponder::BuildAuthData(
    const Group120Var1& challenge,
    const std::vector<uint8_t>& challengeData,
    const std::vector<uint8_t>& originalAPDU
) {
    std::vector<uint8_t> authData;

    // IEEE 1815-2012 Table 7-9: MAC input = CSQ || USR || ChallengeData || APDU
    authData.push_back(challenge.csq & 0xFF);
    authData.push_back((challenge.csq >> 8) & 0xFF);
    authData.push_back((challenge.csq >> 16) & 0xFF);
    authData.push_back((challenge.csq >> 24) & 0xFF);
    authData.push_back(challenge.userNumber & 0xFF);
    authData.push_back((challenge.userNumber >> 8) & 0xFF);

    // Challenge data BEFORE APDU
    authData.insert(authData.end(), challengeData.begin(), challengeData.end());

    // Full Application Layer fragment (AppCtrl + FC + objects)
    authData.insert(authData.end(), originalAPDU.begin(), originalAPDU.end());

    return authData;
}

std::vector<uint8_t> SAResponder::CalculateMAC(MACAlgorithm algo,
                                                const std::array<uint8_t, 32>& key,
                                                const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> mac;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;

    switch (algo)
    {
    case MACAlgorithm::HMAC_SHA256_TRUNC_8:   // FIX: was TRUNC_16 with truncation to 16
        HMAC(EVP_sha256(), key.data(), 16, data.data(), data.size(), digest, &digestLen);
        if (digestLen >= 8)
            mac.assign(digest, digest + 8);
        break;

    case MACAlgorithm::HMAC_SHA256_TRUNC_16:  // FIX: was TRUNC_8 with truncation to 8
        HMAC(EVP_sha256(), key.data(), 16, data.data(), data.size(), digest, &digestLen);
        if (digestLen >= 16)
            mac.assign(digest, digest + 16);
        break;

    case MACAlgorithm::HMAC_SHA1_TRUNC_10:
        HMAC(EVP_sha1(), key.data(), 16, data.data(), data.size(), digest, &digestLen);
        if (digestLen >= 10)
            mac.assign(digest, digest + 10);
        break;

    case MACAlgorithm::AES_GMAC:
    {
        if (data.size() < 12)
        {
            Log("ERROR", "AES-GMAC requires at least 12 bytes for nonce");
            break;
        }
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) break;
        unsigned char tag[16];
        int len = 0;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), data.data()) != 1 ||
            EVP_EncryptUpdate(ctx, nullptr, &len, data.data(), (int)data.size()) != 1 ||
            EVP_EncryptFinal_ex(ctx, nullptr, &len) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
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

std::vector<uint8_t> SAResponder::OnChallenge(const Group120Var1& challenge,
                                               const std::vector<uint8_t>& challengeData,
                                               const std::vector<uint8_t>& originalAPDU)
{
    std::vector<uint8_t> emptyResult;

    // Step 1: Validate user has valid session keys
    if (!HasValidKeys(challenge.userNumber))
    {
        std::ostringstream oss;
        oss << "Challenge rejected: User " << challenge.userNumber << " has no valid keys";
        Log("ERROR", oss.str());
        return emptyResult;
    }

    UserSession& session = sessions_[challenge.userNumber];

    // Step 2: CSQ replay detection (IEEE 1815-2012 Section 7.2.3.4)
    // Note: Simple implementation checks if CSQ equals last seen
    // Production systems should maintain a window of recent CSQs
    if (challenge.csq == session.lastCSQ && session.lastCSQ != 0)
    {
        std::ostringstream oss;
        oss << "Challenge rejected: CSQ replay detected (CSQ=" << challenge.csq << ")";
        Log("WARN", oss.str());
        return emptyResult;
    }

    // Step 3: Build authentication data (challenge header || ASDU || challenge data)
    std::vector<uint8_t> authData = BuildAuthData(challenge, challengeData, originalAPDU);

    // Step 4: Calculate MAC using control direction key
    MACAlgorithm algo = static_cast<MACAlgorithm>(challenge.macAlgorithm);
    std::vector<uint8_t> macValue = CalculateMAC(algo, session.controlKey, authData);

    if (macValue.empty())
    {
        Log("ERROR", "MAC calculation failed");
        return emptyResult;
    }

    // Step 5: Update CSQ tracking
    session.lastCSQ = challenge.csq;

    // Step 6: Build g120v2 Reply
    Group120Var2 reply;
    reply.csq = challenge.csq;           // Echo CSQ exactly
    reply.userNumber = challenge.userNumber;

    std::vector<uint8_t> replyBytes = Group120Builder::BuildAuthReply(reply, macValue);

    std::ostringstream oss;
    oss << "Challenge accepted: User=" << challenge.userNumber 
        << ", CSQ=" << challenge.csq 
        << ", MAC=" << macValue.size() << " bytes";
    Log("INFO", oss.str());

    return replyBytes;
}

void SAResponder::OnAuthError(const Group120Var7& error,
                              const std::vector<uint8_t>& errorText)
{
    std::ostringstream oss;
    oss << "Auth Error received: User=" << error.userNumber
        << ", CSQ=" << error.csq
        << ", Code=" << static_cast<int>(error.errorCode)
        << ", AssocId=" << error.assocId;

    if (!errorText.empty())
    {
        std::string text(errorText.begin(), errorText.end());
        oss << ", Text=\"" << text << "\"";
    }

    Log("ERROR", oss.str());

    // IEEE 1815-2012 Section 7.5.7: Actions on authentication failure
    AuthErrorCode code = static_cast<AuthErrorCode>(error.errorCode);
    
    switch (code)
    {
    case AuthErrorCode::AUTHENTICATION_FAILED:
        // May invalidate session keys depending on security policy
        // For now, log but keep keys (allow retry)
        Log("WARN", "Authentication failed - consider key refresh");
        break;

    case AuthErrorCode::UNAUTHORIZED_OPERATION:
        Log("WARN", "User lacks permission for requested operation");
        break;

    case AuthErrorCode::MAX_SESSION_KEY_REACHED:
        Log("ERROR", "Session key limit exceeded - key change required");
        InvalidateKeys(error.userNumber);
        break;

    default:
        break;
    }

    // TODO: Update security statistics (object group 121 if implemented)
}

} // namespace opendnp3
