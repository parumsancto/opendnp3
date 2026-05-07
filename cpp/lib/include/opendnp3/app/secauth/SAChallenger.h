/*
 * SAChallenger.h - DNP3 SAv5 Challenge generator and reply validator
 * Per IEEE 1815-2012 Section 7.5.5.1
 */
#pragma once

#include "opendnp3/app/secauth/Group120.h"
#include "opendnp3/app/secauth/SAMode.h"
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace opendnp3
{

class SAChallenger
{
public:
    using LogCallback = std::function<void(const char* severity, const std::string& msg)>;

    explicit SAChallenger(SAMode mode = SAMode::SAV5);
    ~SAChallenger() = default;

    void SetLogCallback(LogCallback cb);

    // Generates g120v1 Challenge bytes; stores challenge state for ValidateReply
    std::vector<uint8_t> GenerateChallenge(uint16_t userNum,
                                            MACAlgorithm algo,
                                            ChallengeReason reason);

    // Validates g120v2 Reply from master
   bool ValidateReply(const Group120Var2& reply,
        const std::vector<uint8_t>& receivedMAC,
        const std::vector<uint8_t>& challengeAPDU,   // full AL fragment of g120v1
        const std::vector<uint8_t>& challengedAPDU,  // full AL fragment of WRITE req
        const std::array<uint8_t, 32>& controlKey,
        int keyLen = 16
    );

    void Reset();

private:
    void Log(const char* severity, const std::string& msg);

    std::vector<uint8_t> ComputeHMAC(MACAlgorithm algo,
        const std::array<uint8_t, 32>& key,
        const std::vector<uint8_t>& data,
        int keyLen = 16);

    SAMode mode_;
    LogCallback logCallback_;
    uint32_t currentCSQ_     = 0;
    uint16_t currentUser_    = 0;
    MACAlgorithm currentAlgo_ = MACAlgorithm::HMAC_SHA256_TRUNC_8;
    ChallengeReason currentReason_ = ChallengeReason::CRITICAL;
    std::vector<uint8_t> challengeData_;
    bool hasPendingChallenge_ = false;
};

} // namespace opendnp3
