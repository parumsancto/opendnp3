/*
 * SAChallenger.cpp - DNP3 SAv5 Outstation challenge-response
 * IEEE 1815-2012 Section 7.5.5.1
 */
#include "opendnp3/app/secauth/SAChallenger.h"
#include "opendnp3/app/secauth/Group120Builder.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <cstring>
#include <sstream>

namespace opendnp3
{

SAChallenger::SAChallenger(SAMode mode)
    : mode_(mode)
{
}

void SAChallenger::SetLogCallback(LogCallback cb)
{
    logCallback_ = cb;
}

void SAChallenger::Log(const char* severity, const std::string& msg)
{
    if (logCallback_) logCallback_(severity, msg);
}

std::vector<uint8_t> SAChallenger::GenerateChallenge(uint16_t userNum,
                                                       MACAlgorithm algo,
                                                       ChallengeReason reason)
{
    ++currentCSQ_;
    currentUser_   = userNum;
    // SAv2: mandatory HMAC-SHA1-trunc10 regardless of the requested algo.
    currentAlgo_   = (mode_ == SAMode::SAV2) ? MACAlgorithm::HMAC_SHA1_TRUNC_10 : algo;
    currentReason_ = reason;

    // Generate 16 bytes of cryptographically random challenge data
    challengeData_.resize(16);
    if (RAND_bytes(challengeData_.data(), 16) != 1)
    {
        Log("ERROR", "RAND_bytes failed for challenge data");
        return {};
    }

    Group120Var1 hdr;
    hdr.csq          = currentCSQ_;
    hdr.userNumber   = userNum;
    hdr.macAlgorithm = static_cast<uint8_t>(currentAlgo_);
    hdr.reason       = static_cast<uint8_t>(reason);

    std::vector<uint8_t> bytes = Group120Builder::BuildChallenge(hdr, challengeData_);

    hasPendingChallenge_ = true;

    std::ostringstream oss;
    oss << "Challenge generated: CSQ=" << currentCSQ_
        << ", User=" << userNum
        << ", Algo=" << static_cast<int>(hdr.macAlgorithm)
        << ", Reason=" << static_cast<int>(hdr.reason);
    Log("INFO", oss.str());

    return bytes;
}

bool SAChallenger::ValidateReply(
    const Group120Var2& reply,
    const std::vector<uint8_t>& receivedMAC,
    const std::vector<uint8_t>& challengeAPDU,
    const std::vector<uint8_t>& challengedAPDU,
    const std::array<uint8_t, 32>& controlKey,
    int keyLen
) {
    if (!hasPendingChallenge_)
    {
        Log("WARN", "ValidateReply: no pending challenge");
        return false;
    }

    if (reply.csq != currentCSQ_)
    {
        std::ostringstream oss;
        oss << "CSQ mismatch: expected=" << currentCSQ_ << " got=" << reply.csq;
        Log("ERROR", oss.str());
        return false;
    }

    if (reply.userNumber != currentUser_)
    {
        std::ostringstream oss;
        oss << "User mismatch: expected=" << currentUser_ << " got=" << reply.userNumber;
        Log("ERROR", oss.str());
        return false;
    }

    // IEEE 1815-2012 Table A-3: MAC input for Authentication Reply (g120v2):
    //   1. Entire AL fragment of the Challenge message (g120v1) sent by outstation — ALWAYS
    //   2. Entire AL fragment of the challenged ASDU (WRITE request) — if Reason = CRITICAL
    // Masters use the Control Direction Session Key (CDSK) to compute this MAC.
    std::vector<uint8_t> macInput;
    macInput.reserve(challengeAPDU.size() + challengedAPDU.size());
    macInput.insert(macInput.end(), challengeAPDU.begin(),  challengeAPDU.end());
    macInput.insert(macInput.end(), challengedAPDU.begin(), challengedAPDU.end());

    std::vector<uint8_t> expected = ComputeHMAC(currentAlgo_, controlKey, macInput, keyLen);

    if (expected.empty())
    {
        Log("ERROR", "ComputeHMAC returned empty result");
        return false;
    }

    bool valid = (expected.size() == receivedMAC.size() &&
                  std::memcmp(expected.data(), receivedMAC.data(), expected.size()) == 0);

    std::ostringstream oss;
    oss << "Reply MAC " << (valid ? "valid" : "invalid")
        << ": CSQ=" << reply.csq << ", User=" << reply.userNumber;
    Log(valid ? "INFO" : "ERROR", oss.str());

    if (valid)
        hasPendingChallenge_ = false;

    return valid;
}

std::vector<uint8_t> SAChallenger::ComputeHMAC(
    MACAlgorithm algo,
    const std::array<uint8_t, 32>& key,
    const std::vector<uint8_t>& data,
    int keyLen
) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;

    switch (algo)
    {
    case MACAlgorithm::HMAC_SHA256_TRUNC_8:
        // key.data(), 16 — use only first 16 bytes for AES-128 session key
        HMAC(EVP_sha256(), key.data(), keyLen, data.data(), data.size(), digest, &digestLen);
        if (digestLen >= 8) return std::vector<uint8_t>(digest, digest + 8);
        break;

    case MACAlgorithm::HMAC_SHA256_TRUNC_16:
        HMAC(EVP_sha256(), key.data(), keyLen, data.data(), data.size(), digest, &digestLen);
        if (digestLen >= 16) return std::vector<uint8_t>(digest, digest + 16);
        break;

    case MACAlgorithm::HMAC_SHA1_TRUNC_10:
        HMAC(EVP_sha1(), key.data(), keyLen, data.data(), data.size(), digest, &digestLen);
        if (digestLen >= 10) return std::vector<uint8_t>(digest, digest + 10);
        break;

    default:
        Log("ERROR", "SAChallenger: unsupported MAC algorithm");
        break;
    }
    return {};
}

void SAChallenger::Reset()
{
    currentCSQ_ = 0;
    currentUser_ = 0;
    challengeData_.clear();
    hasPendingChallenge_ = false;
}

} // namespace opendnp3
