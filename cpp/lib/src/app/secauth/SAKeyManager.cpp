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

SAKeyManager::SAKeyManager(const std::array<uint8_t, 32>& updateKey)
    : updateKey(updateKey),
      ksq(0),
      keyWrapAlgo(KeyWrapAlgorithm::AES128),
      lastUserNum(0),
      sslCtx_(new OpenSSLContext())
{
    // Auto-detect AES-256: if any byte in the upper 16 bytes is non-zero,
    // the full 32-byte key is in use -> switch to AES-256 Key Wrap (RFC 3394).
    for (size_t i = 16; i < 32; ++i)
    {
        if (updateKey[i] != 0)
        {
            keyWrapAlgo = KeyWrapAlgorithm::AES256;
            break;
        }
    }
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

    appendU32LE(ksq);
    appendU16LE(userNum);
    result.push_back(static_cast<uint8_t>(keyWrapAlgo)); // KWA: 0x01=AES-128, 0x02=AES-256
    result.push_back(static_cast<uint8_t>(status));       // Key Status (NOT_INIT/COMM_FAIL)
    result.push_back(0x00);                               // MAL = 0x00 (no MAC value follows)
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

    uint8_t macAlgoVal = static_cast<uint8_t>(macAlgo);

    // Step 2: MAC input = [KSQ(4LE) || USR(2LE) || KWA(1) || Status=OK(1) || MAL(1) || CDL(2LE) || CD]
    // Per IEEE 1815-2012 Table A-6
    std::vector<uint8_t> macInput;
    auto pushU32LE = [&](uint32_t v) {
        macInput.push_back(v & 0xFF); macInput.push_back((v>>8) & 0xFF);
        macInput.push_back((v>>16) & 0xFF); macInput.push_back((v>>24) & 0xFF);
    };
    auto pushU16LE = [&](uint16_t v) {
        macInput.push_back(v & 0xFF); macInput.push_back((v>>8) & 0xFF);
    };
    pushU32LE(ksq);
    pushU16LE(userNum);
    macInput.push_back(static_cast<uint8_t>(keyWrapAlgo));
    macInput.push_back(static_cast<uint8_t>(KeyStatus::OK));
    macInput.push_back(macAlgoVal);
    pushU16LE(static_cast<uint16_t>(lastChallengeData.size()));
    macInput.insert(macInput.end(), lastChallengeData.begin(), lastChallengeData.end());

    // Step 3: HMAC-SHA-256 truncated to 8 bytes
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    HMAC(EVP_sha256(), monitorKey.data(), sessionKeyLen,
         macInput.data(), macInput.size(), digest, &digestLen);
    constexpr size_t MACTRUNCLEN = 8;
    std::vector<uint8_t> macValue(digest, digest + std::min((size_t)digestLen, MACTRUNCLEN));

    // Step 4: build g120v5 (identical to BuildKeyStatusConfirmation)
    const uint16_t cdl = static_cast<uint16_t>(lastChallengeData.size());
    const uint16_t objSize = 4 + 2 + 1 + 1 + 1 + 2 + cdl + MACTRUNCLEN;

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
    result.push_back(macAlgoVal);                           // MAL
    appendU16LE(cdl);       // CDL
    result.insert(result.end(), lastChallengeData.begin(), lastChallengeData.end()); // CD
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

    constexpr size_t MIN_WRAPPED_LEN  = 24; // 8 IV + 16 data (min)
    constexpr size_t MIN_UNWRAPPED_LEN = 48;  // need at least CDK(16)+MDK(16)+header(2)+some CD

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

    // IEEE 1815-2012 Table A-4: save the entire AL fragment of the Key Change
    // message for use in BuildKeyStatusConfirmation MAC calculation.
    lastKeyChangeAlFragment = keyChangeAlFragment;

    // Read Key Length field (bytes 0-1 LE) to compute field offsets dynamically.
    // IEEE 1815-2012 Table A-5 structure:
    //   KL(2) + CDK(KL) + MDK(KL) + KSQ(4) + USR(2) + KWA(1) + Status(1) + MAL(1) + CDL(2) + CD_OS(CDL)
    // Standard says KL=16 always, but opendnp3 master uses KL=32 when KWA=AES-256.
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

    // Dynamic offsets based on actual KL value
    const size_t cdkOffset  = 2;
    const size_t mdkOffset  = 2 + static_cast<size_t>(kl);
    const size_t cdlOffset  = 2 + 2 * static_cast<size_t>(kl) + 9; // KSQ(4)+USR(2)+KWA(1)+Stat(1)+MAL(1)
    const size_t cdOsOffset = cdlOffset + 2;

    if (unwrapped.size() < cdlOffset + 2)
    {
        std::ostringstream oss;
        oss << "Unwrapped data too short for CDL field (need "
            << (cdlOffset + 2) << ", have " << unwrapped.size() << ")";
        Log("ERROR", oss.str());
        InvalidateKeys(keyChange.userNumber, KeyStatus::AUTH_FAIL);
        return false;
    }

    // Read CDL from plaintext (not from lastChallengeData.size())
    const uint16_t cdl = static_cast<uint16_t>(unwrapped[cdlOffset]) |
                         (static_cast<uint16_t>(unwrapped[cdlOffset + 1]) << 8);

    if (unwrapped.size() < cdOsOffset + static_cast<size_t>(cdl))
    {
        std::ostringstream oss;
        oss << "Unwrapped data too short for CD_OS (need "
            << (cdOsOffset + cdl) << ", have " << unwrapped.size() << ")";
        Log("ERROR", oss.str());
        InvalidateKeys(keyChange.userNumber, KeyStatus::AUTH_FAIL);
        return false;
    }

    // Verify CD_OS matches the challenge data we sent in g120v5
    if (static_cast<size_t>(cdl) != lastChallengeData.size() ||
        std::memcmp(unwrapped.data() + cdOsOffset,
                    lastChallengeData.data(),
                    lastChallengeData.size()) != 0)
    {
        Log("ERROR", "CD_OS mismatch: key change rejected");
        InvalidateKeys(keyChange.userNumber, KeyStatus::AUTH_FAIL);
        return false;
    }
    Log("INFO", "CD_OS verification successful");

    // Extract session keys; copy min(kl, 32) bytes into 32-byte slots
    const size_t copyLen = std::min(static_cast<size_t>(kl), size_t(32));
    controlKeyOut.fill(0);
    monitorKeyOut.fill(0);
    std::memcpy(controlKeyOut.data(), unwrapped.data() + cdkOffset, copyLen);
    std::memcpy(monitorKeyOut.data(), unwrapped.data() + mdkOffset, copyLen);

    // Save actual session key length for use in HMAC calculations
    sessionKeyLen = static_cast<uint16_t>(copyLen);

    userNumOut = keyChange.userNumber;
    keyStatusMap[keyChange.userNumber] = KeyStatus::OK;

    std::ostringstream oss;
    oss << "Key Change successful: User=" << keyChange.userNumber
        << ", KSQ=" << keyChange.ksq
        << ", KL=" << kl;
    Log("INFO", oss.str());
    return true;
}

std::vector<uint8_t> SAKeyManager::BuildKeyStatusConfirmation(
    uint16_t userNum,
    const std::array<uint8_t, 32>& monitorKey,
    MACAlgorithm macAlgo)
{
    // Per IEEE 1815-2012 Table A-4:
    // MAC input = the entire Application Layer fragment of the g120v6 Key Change
    // most recently received from the master. NOT the fields of this g120v5 object.
    if (lastKeyChangeAlFragment.empty())
    {
        Log("ERROR", "BuildKeyStatusConfirmation: no Key Change AL fragment stored");
        return {};
    }

    // Wire-level constants per IEEE 1815-2012 Table 7-4 and Table 7-5
    // constexpr uint8_t KWA_AES128_WIRE     = 0x01;
    constexpr uint8_t STATUS_OK_WIRE      = 0x01;
    constexpr uint8_t MAL_SHA256_8_WIRE   = 0x03;  // HMAC-SHA256 truncated to 8 octets
    constexpr size_t  MAC_TRUNC_LEN       = 8;

    // Compute HMAC-SHA256(MDK, AL_fragment), truncate to 8 bytes
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digestLen = 0;
    HMAC(EVP_sha256(),
         monitorKey.data(), sessionKeyLen,
         lastKeyChangeAlFragment.data(), lastKeyChangeAlFragment.size(),
         digest, &digestLen);

    std::vector<uint8_t> macValue(digest, digest + std::min((size_t)digestLen, MAC_TRUNC_LEN));

    // Build g120v5 object
    const uint16_t cdl     = static_cast<uint16_t>(lastChallengeData.size());
    const uint16_t objSize = static_cast<uint16_t>(4 + 2 + 1 + 1 + 1 + 2 + cdl + macValue.size());

    std::vector<uint8_t> result;
    result.reserve(6 + objSize);

    result.push_back(0x78);
    result.push_back(0x05);
    result.push_back(0x5B);
    result.push_back(0x01);
    result.push_back( objSize       & 0xFF);
    result.push_back((objSize >> 8) & 0xFF);

    // KSQ (4 bytes LE)
    result.push_back( ksq        & 0xFF);
    result.push_back((ksq >>  8) & 0xFF);
    result.push_back((ksq >> 16) & 0xFF);
    result.push_back((ksq >> 24) & 0xFF);
    // USR (2 bytes LE)
    result.push_back( userNum       & 0xFF);
    result.push_back((userNum >> 8) & 0xFF);
    // result.push_back(KWA_AES128_WIRE);
    result.push_back(static_cast<uint8_t>(keyWrapAlgo));
    result.push_back(STATUS_OK_WIRE);
    result.push_back(MAL_SHA256_8_WIRE);
    result.push_back( cdl       & 0xFF);
    result.push_back((cdl >> 8) & 0xFF);
    result.insert(result.end(), lastChallengeData.begin(), lastChallengeData.end());
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
