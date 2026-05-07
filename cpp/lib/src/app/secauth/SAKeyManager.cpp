/*
 * Copyright (c) 2026 parumsancto/opendnp3
 */

#include "opendnp3/app/secauth/SAKeyManager.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace opendnp3
{

struct SAKeyManager::OpenSSLContext
{
    // Placeholder for future state
};

SAKeyManager::SAKeyManager(const std::array<uint8_t, 32>& updateKey, SAMode mode)
    : mode_(mode),
      updateKey(updateKey),
      ksq(0),
      keyWrapAlgo(mode == SAMode::SAV2 ? KeyWrapAlgorithm::AES128 : KeyWrapAlgorithm::AES256),
      lastUserNum(0),
      sslCtx_(new OpenSSLContext())
{
}

SAKeyManager::~SAKeyManager()
{
    delete sslCtx_;
}

void SAKeyManager::SetLogCallback(LogCallback callback)
{
    logCallback_ = callback;
}

void SAKeyManager::Log(const char* severity, const std::string& message)
{
    if (logCallback_)
    {
        logCallback_(severity, message);
    }
}

void SAKeyManager::SetKeyWrapAlgorithm(KeyWrapAlgorithm algo)
{
    keyWrapAlgo = algo;
    
    std::ostringstream oss;
    oss << "Key wrap algorithm set to " 
        << (algo == KeyWrapAlgorithm::AES128 ? "AES-128" : "AES-256");
    Log("INFO", oss.str());
}

KeyWrapAlgorithm SAKeyManager::GetKeyWrapAlgorithm() const
{
    return keyWrapAlgo;
}

std::vector<uint8_t> SAKeyManager::GenerateRandomChallengeData()
{
    // IEEE 1815-2012 Table 7-17: Challenge Data size must match the MAC algorithm.
    // For SHA-256 HMAC: 256 bits = 32 octets.
    // For SHA-1 HMAC:   160 bits = 20 octets.
    // Using 32 bytes covers both SHA-256 and AES-GMAC requirements.
    constexpr size_t CHALLENGE_LEN = 32;  // was 16 — fix per Table 7-17
    std::vector<uint8_t> challengeData(CHALLENGE_LEN);

    if (RAND_bytes(challengeData.data(), CHALLENGE_LEN) != 1)
    {
        Log("ERROR", "RAND_bytes failed for challenge data");
        // Fallback with proper seeding (NOT SECURE — for testing only)
        srand(static_cast<unsigned>(time(nullptr)));
        for (size_t i = 0; i < CHALLENGE_LEN; ++i)
            challengeData[i] = static_cast<uint8_t>(rand() & 0xFF);
    }
    return challengeData;
}

std::vector<uint8_t> SAKeyManager::OnKeyStatusRequest(uint16_t userNum)
{
    // Step 1: Increment KSQ, generate new challenge data
    ++ksq;
    lastChallengeData = GenerateRandomChallengeData();
    lastUserNum = userNum;

    KeyStatus status = GetKeyStatus(userNum);

    // Per IEEE 1815-2012 Table 7-4: when Key Status != OK, MAC Value is absent.
    // objSize = KSQ(4) + USR(2) + KWA(1) + Status(1) + MAL(1) + CDL(2) + CD(N)
    // No MAC bytes — MAL=0x00 signals "no MAC".
    const uint16_t cdl     = static_cast<uint16_t>(lastChallengeData.size());
    const uint16_t objSize = static_cast<uint16_t>(4 + 2 + 1 + 1 + 1 + 2 + cdl);

    std::vector<uint8_t> result;
    result.reserve(6 + objSize);

    // DNP3 object header: Group(1) + Var(1) + Qualifier(1) + Count(1) + ObjSize(2)
    result.push_back(0x78); // Group 120
    result.push_back(0x05); // Variation 5
    result.push_back(0x5B); // Qualifier: 16-bit free-format
    result.push_back(0x01); // Count = 1
    result.push_back( objSize & 0xFF);
    result.push_back((objSize >> 8) & 0xFF);

    auto appendU32LE = [&](uint32_t v) {
        result.push_back( v        & 0xFF);
        result.push_back((v >>  8) & 0xFF);
        result.push_back((v >> 16) & 0xFF);
        result.push_back((v >> 24) & 0xFF);
    };
    auto appendU16LE = [&](uint16_t v) {
        result.push_back( v       & 0xFF);
        result.push_back((v >> 8) & 0xFF);
    };

    // When Status != OK there is no MAC field — MAL must be 0x00 per IEEE 1815-2012 Table 7-4.
    // (Setting a non-zero MAL without a MAC body causes Wireshark/masters to flag the packet.)
    const uint8_t malByte = 0x00;

    appendU32LE(ksq);
    appendU16LE(userNum);
    result.push_back(static_cast<uint8_t>(keyWrapAlgo)); // KWA: 0x01=AES-128, 0x02=AES-256
    result.push_back(static_cast<uint8_t>(status));       // Key Status (NOT_INIT/COMM_FAIL)
    result.push_back(malByte);                            // MAL
    appendU16LE(cdl);
    result.insert(result.end(),
                  lastChallengeData.begin(),
                  lastChallengeData.end());

    std::ostringstream oss;
    oss << "Key Status Request: KSQ=" << ksq
        << ", User=" << userNum
        << ", Status=" << static_cast<int>(status)
        << ", Algo=" << static_cast<int>(keyWrapAlgo);
    Log("INFO", oss.str());

    return result;
}

std::vector<uint8_t> SAKeyManager::OnKeyStatusRequestWithMAC(
    uint16_t userNum,
    const std::array<uint8_t, 32>& monitorKey,
    MACAlgorithm macAlgo
) {
    // Step 1: increment KSQ, new challenge data
    ksq++;
    lastChallengeData = GenerateRandomChallengeData();
    lastUserNum = userNum;

    // SAv2 always uses HMAC-SHA1-trunc10 regardless of the macAlgo parameter.
    const MACAlgorithm effectiveAlgo = (mode_ == SAMode::SAV2)
        ? MACAlgorithm::HMAC_SHA1_TRUNC_10
        : macAlgo;
    const uint8_t macAlgoVal = static_cast<uint8_t>(effectiveAlgo);
    const uint16_t macKeyLen = (mode_ == SAMode::SAV2) ? 16u : sessionKeyLen;

    const EVP_MD* hashFn = (mode_ == SAMode::SAV2) ? EVP_sha1() : EVP_sha256();
    const size_t macTruncLen = (mode_ == SAMode::SAV2) ? 10u : 8u;

    const uint16_t cdl = static_cast<uint16_t>(lastChallengeData.size());
    const uint16_t objSize = static_cast<uint16_t>(4 + 2 + 1 + 1 + 1 + 2 + cdl + macTruncLen);

    std::vector<uint8_t> result;
    result.reserve(6 + objSize);
    result.push_back(0x78); result.push_back(0x05); // Group 120 Var 5
    result.push_back(0x5B); result.push_back(0x01); // Qualifier count=1
    result.push_back(objSize & 0xFF); result.push_back((objSize >> 8) & 0xFF);

    auto appendU32LE = [&](uint32_t v) {
        result.push_back(v&0xFF); result.push_back((v>>8)&0xFF);
        result.push_back((v>>16)&0xFF); result.push_back((v>>24)&0xFF);
    };
    auto appendU16LE = [&](uint16_t v) {
        result.push_back(v&0xFF); result.push_back((v>>8)&0xFF);
    };
    appendU32LE(ksq);       // KSQ
    appendU16LE(userNum);   // USR
    result.push_back(static_cast<uint8_t>(keyWrapAlgo));   // KWA
    result.push_back(static_cast<uint8_t>(KeyStatus::OK)); // Status=OK
    result.push_back(macAlgoVal);                           // MAL (must appear before MAC computation)
    appendU16LE(cdl);       // CDL
    result.insert(result.end(), lastChallengeData.begin(), lastChallengeData.end()); // CD

    // Per SAv2 Table A-6: MAC input = g120v5 body (KSQ+USR+KWA+Status+MAL+CDL+CD),
    // i.e., result bytes after the 6-byte DNP3 object header [G][V][Q][cnt][sz_lo][sz_hi].
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    HMAC(hashFn, monitorKey.data(), macKeyLen,
         result.data() + 6, result.size() - 6, digest, &digestLen);
    std::vector<uint8_t> macValue(digest, digest + std::min((size_t)digestLen, macTruncLen));
    result.insert(result.end(), macValue.begin(), macValue.end()); // MAC

    std::ostringstream oss;
    oss << "Key Status Request (Status=OK): KSQ=" << ksq
        << ", User=" << userNum << ", MAC=" << macValue.size() << " bytes";
    Log("INFO", oss.str());

    return result;
}

std::vector<uint8_t> SAKeyManager::AESKeyUnwrap(const std::vector<uint8_t>& wrappedData)
{
    // RFC 3394 AES Key Unwrap
    // Input: 8-byte IV + N bytes encrypted (N кратне 8, N >= 16)
    // Output: N-8 bytes (ми очікуємо хоча б 32 байти для двох сесійних ключів)

    constexpr size_t MIN_WRAPPED_LEN = 24; // 8 IV + 16 data (min)
    // SAv2 plaintext (Geo SCADA / IEEE 1815 format): KL(2)+CDK(KL)+MDK(KL)+KSQ(4)+USR(2)+KWA+Stat+MAL+CDL+CD
    // For KL=16 and CDL=32: 2+16+16+4+2+1+1+1+2+32 = 77 bytes, padded to 80 for RFC 3394 alignment.
    // SAv5 plaintext: same structure, same minimum size.
    const size_t MIN_UNWRAPPED_LEN = 40u; // covers both modes; actual will be 77-80 bytes

    if (wrappedData.size() < MIN_WRAPPED_LEN || (wrappedData.size() % 8) != 0)
    {
        std::ostringstream oss;
        oss << "AES Key Unwrap failed: invalid length " << wrappedData.size();
        Log("ERROR", oss.str());
        return {};
    }

    size_t wrappedLen   = wrappedData.size();
    size_t unwrappedLen = wrappedLen - 8; // RFC 3394: outlen = inlen - 8

    if (unwrappedLen < MIN_UNWRAPPED_LEN)
    {
        std::ostringstream oss;
        oss << "AES Key Unwrap failed: unwrapped too short " << unwrappedLen;
        Log("ERROR", oss.str());
        return {};
    }

    std::vector<uint8_t> unwrapped(unwrappedLen);

    AES_KEY aesKey;
    int keyBits = (keyWrapAlgo == KeyWrapAlgorithm::AES256) ? 256 : 128;

    if (AES_set_decrypt_key(updateKey.data(), keyBits, &aesKey) != 0)
    {
        Log("ERROR", "AES_set_decrypt_key failed");
        return {};
    }

    // Unpack all wrappedData
    int result = AES_unwrap_key(&aesKey,
                                nullptr, // стандартний IV 0xA6...A6
                                unwrapped.data(),
                                wrappedData.data(),
                                static_cast<int>(wrappedLen));

    if (result <= 0)
    {
        std::ostringstream oss;
        oss << "AES_unwrap_key failed: returned " << result;
        Log("ERROR", oss.str());
        return {};
    }

    if (static_cast<size_t>(result) != unwrappedLen)
    {
        std::ostringstream oss;
        oss << "AES_unwrap_key size mismatch: got " << result
            << ", expected " << unwrappedLen;
        Log("ERROR", oss.str());
        return {};
    }

    Log("INFO", "AES Key Unwrap successful");
    return unwrapped;
}

bool SAKeyManager::OnKeyChange(const Group120Var6& keyChange,
                                const std::vector<uint8_t>& wrappedKeyData,
                                const std::vector<uint8_t>& keyChangeAlFragment,
                                uint16_t& userNumOut,
                                std::array<uint8_t, 32>& controlKeyOut,
                                std::array<uint8_t, 32>& monitorKeyOut)
{
    if (keyChange.ksq != ksq)
    {
        std::ostringstream oss;
        oss << "Key Change KSQ mismatch: expected " << ksq
            << ", received " << keyChange.ksq;
        Log("ERROR", oss.str());
        return false;
    }

    if (keyChange.userNumber != lastUserNum)
    {
        std::ostringstream oss;
        oss << "Key Change user mismatch: expected " << lastUserNum
            << ", received " << keyChange.userNumber;
        Log("WARN", oss.str());
    }

    std::vector<uint8_t> unwrapped = AESKeyUnwrap(wrappedKeyData);
    if (unwrapped.empty())
    {
        Log("ERROR", "Key Change failed: AES unwrap error");
        InvalidateKeys(keyChange.userNumber, KeyStatus::AUTH_FAIL);
        return false;
    }

    // Save the entire AL fragment for MAC computation in BuildKeyStatusConfirmation.
    // Both SAv2 and SAv5 MAC the full AL fragment of the received g120v6.
    lastKeyChangeAlFragment = keyChangeAlFragment;

    if (unwrapped.size() < 2)
    {
        Log("ERROR", "Unwrapped data too short to read KL field");
        InvalidateKeys(keyChange.userNumber, KeyStatus::AUTH_FAIL);
        return false;
    }

    const uint16_t kl = static_cast<uint16_t>(unwrapped[0]) |
                        (static_cast<uint16_t>(unwrapped[1]) << 8);

    if (kl != 16 && kl != 32)
    {
        std::ostringstream oss;
        oss << "Unexpected KL in key wrap plaintext: " << kl;
        Log("WARN", oss.str());
    }

    const size_t cdkOffset = 2;
    const size_t mdkOffset = 2 + static_cast<size_t>(kl);

    {
        // Plaintext structure (SAv2 and SAv5): KL(2)+CDK(KL)+MDK(KL)+KSQ(4)+USR(2)+KWA(1)+Stat(1)+MAL(1)+CDL(2)+CD_OS(CDL)
        // Geo SCADA SAv2 uses the same key-wrap plaintext format as SAv5 — the only
        // differences are AES-128 (vs AES-256) and SHA-1 (vs SHA-256) algorithms.
        const size_t ksqOffset  = 2 + 2 * static_cast<size_t>(kl);          // after KL+CDK+MDK
        const size_t cdlOffset  = ksqOffset + 4 + 2 + 1 + 1 + 1;            // after KSQ+USR+KWA+Stat+MAL
        const size_t cdOsOffset = cdlOffset + 2;

        if (unwrapped.size() >= cdlOffset + 2)
        {
            // Verify KSQ embedded in the plaintext
            const uint32_t embeddedKSQ =
                static_cast<uint32_t>(unwrapped[ksqOffset])
                | (static_cast<uint32_t>(unwrapped[ksqOffset + 1]) << 8)
                | (static_cast<uint32_t>(unwrapped[ksqOffset + 2]) << 16)
                | (static_cast<uint32_t>(unwrapped[ksqOffset + 3]) << 24);

            if (embeddedKSQ != ksq)
            {
                std::ostringstream oss;
                oss << "KSQ mismatch in key wrap plaintext: expected " << ksq
                    << ", got " << embeddedKSQ;
                Log("ERROR", oss.str());
                InvalidateKeys(keyChange.userNumber, KeyStatus::AUTH_FAIL);
                return false;
            }

            // Verify CD_OS (challenge data echo)
            const uint16_t cdl = static_cast<uint16_t>(unwrapped[cdlOffset]) |
                                 (static_cast<uint16_t>(unwrapped[cdlOffset + 1]) << 8);

            if (unwrapped.size() >= cdOsOffset + static_cast<size_t>(cdl) &&
                static_cast<size_t>(cdl) == lastChallengeData.size())
            {
                if (std::memcmp(unwrapped.data() + cdOsOffset,
                                lastChallengeData.data(),
                                lastChallengeData.size()) != 0)
                {
                    Log("ERROR", "CD_OS mismatch in key wrap plaintext — key change rejected");
                    InvalidateKeys(keyChange.userNumber, KeyStatus::AUTH_FAIL);
                    return false;
                }
            }
            Log("INFO", "Key wrap plaintext: KSQ and CD_OS verified successfully");
        }
        else
        {
            // Short plaintext (legacy format): just verify KSQ at the minimum offset
            const size_t minKsqLen = ksqOffset + 6;
            if (unwrapped.size() >= minKsqLen)
            {
                const uint32_t embeddedKSQ =
                    static_cast<uint32_t>(unwrapped[ksqOffset])
                    | (static_cast<uint32_t>(unwrapped[ksqOffset + 1]) << 8)
                    | (static_cast<uint32_t>(unwrapped[ksqOffset + 2]) << 16)
                    | (static_cast<uint32_t>(unwrapped[ksqOffset + 3]) << 24);

                if (embeddedKSQ != ksq)
                {
                    std::ostringstream oss;
                    oss << "KSQ mismatch in short key wrap plaintext: expected " << ksq
                        << ", got " << embeddedKSQ;
                    Log("ERROR", oss.str());
                    InvalidateKeys(keyChange.userNumber, KeyStatus::AUTH_FAIL);
                    return false;
                }
                Log("INFO", "Key wrap plaintext: KSQ verified (short format, no CD_OS)");
            }
        }
    }

    // Extract session keys; copy min(kl, 32) bytes into 32-byte slots
    const size_t copyLen = std::min(static_cast<size_t>(kl), size_t(32));
    controlKeyOut.fill(0);
    monitorKeyOut.fill(0);
    std::memcpy(controlKeyOut.data(), unwrapped.data() + cdkOffset, copyLen);
    std::memcpy(monitorKeyOut.data(), unwrapped.data() + mdkOffset, copyLen);

    sessionKeyLen = static_cast<uint16_t>(copyLen);

    userNumOut = keyChange.userNumber;
    keyStatusMap[keyChange.userNumber] = KeyStatus::OK;

    std::ostringstream oss;
    oss << "Key Change successful: User=" << keyChange.userNumber
        << ", KSQ=" << keyChange.ksq
        << ", KL=" << kl
        << ", Mode=" << (mode_ == SAMode::SAV2 ? "SAv2" : "SAv5");
    Log("INFO", oss.str());
    return true;
}

std::vector<uint8_t> SAKeyManager::BuildKeyStatusConfirmation(
    uint16_t userNum,
    const std::array<uint8_t, 32>& monitorKey,
    MACAlgorithm macAlgo)
{
    constexpr uint8_t STATUS_OK_WIRE = 0x01;

    const EVP_MD*  hashFn     = (mode_ == SAMode::SAV2) ? EVP_sha1()   : EVP_sha256();
    const size_t   macTruncLen = (mode_ == SAMode::SAV2) ? 10u          : 8u;
    const uint16_t macKeyLen  = (mode_ == SAMode::SAV2) ? 16u          : sessionKeyLen;
    const uint8_t  malByte    = static_cast<uint8_t>(macAlgo);

    const uint16_t cdl     = static_cast<uint16_t>(lastChallengeData.size());
    const uint16_t objSize = static_cast<uint16_t>(4 + 2 + 1 + 1 + 1 + 2 + cdl + macTruncLen);

    std::vector<uint8_t> result;
    result.reserve(6 + objSize);

    result.push_back(0x78);
    result.push_back(0x05);
    result.push_back(0x5B);
    result.push_back(0x01);
    result.push_back( objSize       & 0xFF);
    result.push_back((objSize >> 8) & 0xFF);

    result.push_back( ksq        & 0xFF);
    result.push_back((ksq >>  8) & 0xFF);
    result.push_back((ksq >> 16) & 0xFF);
    result.push_back((ksq >> 24) & 0xFF);
    result.push_back( userNum       & 0xFF);
    result.push_back((userNum >> 8) & 0xFF);
    result.push_back(static_cast<uint8_t>(keyWrapAlgo));
    result.push_back(STATUS_OK_WIRE);
    result.push_back(malByte);                           // MAL must precede MAC computation
    result.push_back( cdl       & 0xFF);
    result.push_back((cdl >> 8) & 0xFF);
    result.insert(result.end(), lastChallengeData.begin(), lastChallengeData.end());

    // Per IEEE 1815-2012 Table A-6: MAC input for Key Status OK (g120v5 after g120v6) =
    // the complete AL fragment of the g120v6 Key Change message that triggered this response.
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digestLen = 0;
    HMAC(hashFn, monitorKey.data(), macKeyLen,
         lastKeyChangeAlFragment.data(), static_cast<int>(lastKeyChangeAlFragment.size()), digest, &digestLen);
    std::vector<uint8_t> macValue(digest, digest + std::min((size_t)digestLen, macTruncLen));
    result.insert(result.end(), macValue.begin(), macValue.end());

    return result;
}

uint32_t SAKeyManager::GetKSQ() const
{
    return ksq;
}

KeyStatus SAKeyManager::GetKeyStatus(uint16_t userNum) const
{
    auto it = keyStatusMap.find(userNum);
    if (it != keyStatusMap.end())
    {
        return it->second;
    }
    
    // Default: keys not initialized
    return KeyStatus::NOT_INIT;
}

void SAKeyManager::InvalidateKeys(uint16_t userNum, KeyStatus status)
{
    keyStatusMap[userNum] = status;

    std::ostringstream oss;
    oss << "Keys invalidated for user " << userNum 
        << ", status=" << static_cast<int>(status);
    Log("WARN", oss.str());
}

} // namespace opendnp3
