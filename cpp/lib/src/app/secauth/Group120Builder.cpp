/*
 * Copyright (c) 2026 parumsancto/opendnp3
 */

#include "opendnp3/app/secauth/Group120Builder.h"
#include "opendnp3/gen/FunctionCode.h"
#include <cstring>

namespace opendnp3
{

void Group120Builder::BuildObjectHeader(std::vector<uint8_t>& buf,
                                         uint8_t group,
                                         uint8_t variation,
                                         uint16_t length)
{
    buf.push_back(group);           // Group 120
    buf.push_back(variation);       // Variation 1-15
    buf.push_back(QUAL_VAR_LENGTH); // Qualifier 0x5B
    buf.push_back(1);               // Count = 1 
    buf.push_back(static_cast<uint8_t>(length & 0xFF));        // Size LSB
    buf.push_back(static_cast<uint8_t>((length >> 8) & 0xFF)); // Size MSB
}

std::vector<uint8_t> Group120Builder::BuildChallenge(const Group120Var1& ch,
                                                      const std::vector<uint8_t>& challengeData)
{
    std::vector<uint8_t> result;
    
    // Validate challenge data length
    if (challengeData.size() < MIN_CHALLENGE_DATA_LENGTH || 
        challengeData.size() > MAX_CHALLENGE_DATA_LENGTH)
        return result; // Empty = error

    uint16_t objLen = static_cast<uint16_t>(sizeof(Group120Var1)
        + static_cast<uint16_t>(challengeData.size()));
    
    // Object header
    BuildObjectHeader(result, 120, 1, objLen);

    // Fixed fields
    WriteUInt32LE(result, ch.csq);
    WriteUInt16LE(result, ch.userNumber);
    result.push_back(ch.macAlgorithm);
    result.push_back(ch.reason);

    // Variable challenge data
    result.insert(result.end(), challengeData.begin(), challengeData.end());

    return result;
}

std::vector<uint8_t> Group120Builder::BuildAuthReply(const Group120Var2& reply,
                                                      const std::vector<uint8_t>& macValue)
{
    std::vector<uint8_t> result;

    if (macValue.empty())
        return result;

    uint16_t objLen = static_cast<uint16_t>(sizeof(Group120Var2)
        + static_cast<uint16_t>(macValue.size()));
    BuildObjectHeader(result, 120, 2, objLen);

    WriteUInt32LE(result, reply.csq);
    WriteUInt16LE(result, reply.userNumber);
    result.insert(result.end(), macValue.begin(), macValue.end());

    return result;
}

std::vector<uint8_t> Group120Builder::BuildAggressiveModeReq(const Group120Var3& aggr)
{
    std::vector<uint8_t> result;

    BuildObjectHeader(result, 120, 3, static_cast<uint16_t>(sizeof(Group120Var3)));
    WriteUInt32LE(result, aggr.csq);
    WriteUInt16LE(result, aggr.userNumber);

    return result;
}

std::vector<uint8_t> Group120Builder::BuildKeyStatusRequest(const Group120Var4& ksr)
{
    std::vector<uint8_t> result;

    BuildObjectHeader(result, 120, 4, static_cast<uint16_t>(sizeof(Group120Var4)));
    WriteUInt16LE(result, ksr.userNumber);

    return result;
}

std::vector<uint8_t> Group120Builder::BuildKeyStatus(const Group120Var5& ks,
                                                      const std::vector<uint8_t>& challengeData)
{
    std::vector<uint8_t> result;

    // Wire: KSQ(4)+User(2)+KWA(1)+Status(1)+MAL(1)+CDL(2)+ChallengeData(N)
    // = 11 fixed bytes + N challenge bytes (+ MAC Value if macAlgorithm != 0)
    uint16_t cdLen  = static_cast<uint16_t>(challengeData.size());
    uint16_t objLen = static_cast<uint16_t>(11 + cdLen);  // MAL=0 → no MAC appended
    BuildObjectHeader(result, 120, 5, objLen);

    WriteUInt32LE(result, ks.ksq);
    WriteUInt16LE(result, ks.userNumber);
    result.push_back(ks.keyWrapAlgo);
    result.push_back(ks.status);
    result.push_back(ks.macAlgorithm);   // ← MAC Algorithm (0 = no MAC)
    WriteUInt16LE(result, cdLen);         // ← Challenge Data Length (2 bytes LE)

    if (!challengeData.empty())
        result.insert(result.end(), challengeData.begin(), challengeData.end());

    // No MAC Value bytes when macAlgorithm == 0 (NOT_INIT state)
    return result;
}

std::vector<uint8_t> Group120Builder::BuildKeyChange(const Group120Var6& kc,
                                                      const std::vector<uint8_t>& wrappedKeyData)
{
    std::vector<uint8_t> result;

    if (wrappedKeyData.empty())
        return result;

    uint16_t objLen = static_cast<uint16_t>(sizeof(Group120Var6)
        + static_cast<uint16_t>(wrappedKeyData.size()));
    BuildObjectHeader(result, 120, 6, objLen);

    WriteUInt32LE(result, kc.ksq);
    WriteUInt16LE(result, kc.userNumber);
    result.insert(result.end(), wrappedKeyData.begin(), wrappedKeyData.end());

    return result;
}

std::vector<uint8_t> Group120Builder::BuildAuthError(const Group120Var7& err,
                                                      const std::vector<uint8_t>& errorText)
{
    std::vector<uint8_t> result;

    uint16_t objLen = static_cast<uint16_t>(sizeof(Group120Var7)
        + static_cast<uint16_t>(errorText.size()));
    BuildObjectHeader(result, 120, 7, objLen);

    WriteUInt32LE(result, err.csq);
    WriteUInt16LE(result, err.userNumber);
    WriteUInt16LE(result, err.assocId);
    result.push_back(err.errorCode);
    result.insert(result.end(), err.timeOfError, err.timeOfError + 6);

    if (!errorText.empty())
        result.insert(result.end(), errorText.begin(), errorText.end());

    return result;
}

std::vector<uint8_t> Group120Builder::BuildHMAC(const std::vector<uint8_t>& macValue)
{
    std::vector<uint8_t> result;

    if (macValue.empty())
        return result;

    // g120v9 has NO fixed fields - MAC starts at offset 0
    BuildObjectHeader(result, 120, 9, static_cast<uint16_t>(macValue.size()));
    result.insert(result.end(), macValue.begin(), macValue.end());

    return result;
}

std::vector<uint8_t> Group120Builder::BuildAuthResponse(FunctionCode fc,
                                                         const std::vector<uint8_t>& objects)
{
    std::vector<uint8_t> result;

    // Function code
    result.push_back(static_cast<uint8_t>(fc));

    // IIN bytes [0x00, 0x00]
    result.push_back(0x00);
    result.push_back(0x00);

    // Concatenated Group 120 objects
    result.insert(result.end(), objects.begin(), objects.end());

    return result;
}

} // namespace opendnp3
