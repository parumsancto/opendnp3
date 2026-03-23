/*
 * Copyright (c) 2026 parumsancto/opendnp3
 */

#include "opendnp3/app/secauth/Group120Parser.h"

namespace opendnp3
{

bool Group120Parser::ParseChallenge(const uint8_t* data, size_t len,
                                    Group120Var1& out,
                                    std::vector<uint8_t>& challengeData)
{
    // Minimum: 8 bytes fixed + 4 bytes challenge data
    constexpr size_t MIN_LEN = sizeof(Group120Var1) + MIN_CHALLENGE_DATA_LENGTH;
    if (!data || len < MIN_LEN)
        return false;

    // Parse fixed fields
    out.csq = ReadUInt32LE(data);
    out.userNumber = ReadUInt16LE(data + 4);
    out.macAlgorithm = data[6];
    out.reason = data[7];

    // Extract variable challenge data
    size_t challengeLen = len - sizeof(Group120Var1);
    if (challengeLen < MIN_CHALLENGE_DATA_LENGTH || 
        challengeLen > MAX_CHALLENGE_DATA_LENGTH)
        return false;

    challengeData.assign(data + sizeof(Group120Var1), 
                        data + sizeof(Group120Var1) + challengeLen);
    return true;
}

bool Group120Parser::ParseReply(const uint8_t* data, size_t len,
                                Group120Var2& out,
                                std::vector<uint8_t>& macValue)
{
    // Minimum: 6 bytes fixed + MAC value
    constexpr size_t MIN_LEN = sizeof(Group120Var2) + 4;
    if (!data || len < MIN_LEN)
        return false;

    out.csq = ReadUInt32LE(data);
    out.userNumber = ReadUInt16LE(data + 4);

    // Extract MAC value
    size_t macLen = len - sizeof(Group120Var2);
    macValue.assign(data + sizeof(Group120Var2), data + len);
    return true;
}

bool Group120Parser::ParseAggressiveModeReq(const uint8_t* data, size_t len,
                                            Group120Var3& out)
{
    if (!data || len != sizeof(Group120Var3))
        return false;

    out.csq = ReadUInt32LE(data);
    out.userNumber = ReadUInt16LE(data + 4);
    return true;
}

bool Group120Parser::ParseKeyStatusRequest(const uint8_t* data, size_t len,
                                           Group120Var4& out)
{
    if (!data || len != sizeof(Group120Var4))
        return false;

    out.userNumber = ReadUInt16LE(data);
    return true;
}

bool Group120Parser::ParseKeyStatus(const uint8_t* data, size_t len,
                                    Group120Var5& out,
                                    std::vector<uint8_t>& challengeData)
{
    constexpr size_t FIXED_LEN = sizeof(Group120Var5);
    if (!data || len < FIXED_LEN)
        return false;

    out.ksq = ReadUInt32LE(data);
    out.userNumber = ReadUInt16LE(data + 4);
    out.keyWrapAlgo = data[6];
    out.status = data[7];

    // Challenge data is optional
    if (len > FIXED_LEN)
    {
        challengeData.assign(data + FIXED_LEN, data + len);
    }
    return true;
}

bool Group120Parser::ParseKeyChange(const uint8_t* data, size_t len,
                                    Group120Var6& out,
                                    std::vector<uint8_t>& wrappedKeyData)
{
    constexpr size_t MIN_LEN = sizeof(Group120Var6) + 16; // 6 + min key wrap
    if (!data || len < MIN_LEN)
        return false;

    out.ksq = ReadUInt32LE(data);
    out.userNumber = ReadUInt16LE(data + 4);

    constexpr size_t FIXED_OFFSET = 4 + 2; // KSQ(uint32_t) + userNumber(uint16_t)
    wrappedKeyData.assign(data + FIXED_OFFSET, data + len);
    return true;
}

bool Group120Parser::ParseAuthError(const uint8_t* data, size_t len,
                                    Group120Var7& out,
                                    std::vector<uint8_t>& errorText)
{
    constexpr size_t FIXED_LEN = sizeof(Group120Var7);
    if (!data || len < FIXED_LEN)
        return false;

    out.csq = ReadUInt32LE(data);
    out.userNumber = ReadUInt16LE(data + 4);
    out.assocId = ReadUInt16LE(data + 6);
    out.errorCode = data[8];
    std::memcpy(out.timeOfError, data + 9, 6);

    // Error text is optional
    if (len > FIXED_LEN)
    {
        errorText.assign(data + FIXED_LEN, data + len);
    }
    return true;
}

bool Group120Parser::ParseHMAC(const uint8_t* data, size_t len,
                               std::vector<uint8_t>& macValue)
{
    if (!data || len < 4)
        return false;

    macValue.assign(data, data + len);
    return true;
}

bool Group120Parser::Dispatch(const uint8_t* data, size_t len,
                              uint8_t& groupOut, uint8_t& variationOut)
{
    // Minimum: group(1) + variation(1) + qualifier(1) + length(1)
    if (!data || len < 4)
        return false;

    groupOut = data[0];
    variationOut = data[1];

    // Only handle Group 120
    if (groupOut != 120)
        return false;

    // Validate variation range
    return (variationOut >= 1 && variationOut <= 15);
}

} // namespace opendnp3
