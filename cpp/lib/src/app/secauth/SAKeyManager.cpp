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
    : updateKey_(updateKey),
      ksq(0),
      keyWrapAlgo(KeyWrapAlgorithm::AES128),
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
    // IEEE 1815-2012 Section 7.5.5.2 (Step 1 of Figure 7-3)
    
    // Step 1: Increment KSQ
    ++ksq;

    // Step 2: Generate random challenge data (16 bytes)
    lastChallengeData = GenerateRandomChallengeData();
    lastUserNum = userNum;

    // Step 3: Get current key status
    KeyStatus status = GetKeyStatus(userNum);

    // Step 4: Build g120v5 Key Status
    Group120Var5 keyStatus;
    keyStatus.ksq = ksq;
    keyStatus.userNumber = userNum;
    keyStatus.keyWrapAlgo = static_cast<uint8_t>(keyWrapAlgo);
    keyStatus.status = static_cast<uint8_t>(status);
    keyStatus.macAlgorithm = 0;  // 0 = No MAC Value

    std::vector<uint8_t> keyStatusBytes = Group120Builder::BuildKeyStatus(
        keyStatus, lastChallengeData);

    // The initial Key Status response (before Key Change) has no MAC (MAL field
    // indicates what algorithm WILL BE used in the confirmation).
    keyStatusBytes.push_back(static_cast<uint8_t>(MACAlgorithm::HMAC_SHA1_TRUNC_10));

    std::ostringstream oss;
    oss << "Key Status Request: KSQ=" << ksq 
        << ", User=" << userNum
        << ", Status=" << static_cast<int>(status)
        << ", Algo=" << static_cast<int>(keyWrapAlgo);
    Log("INFO", oss.str());

    return keyStatusBytes;
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
    HMAC(EVP_sha256(), monitorKey.data(), 16,
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

    if (AES_set_decrypt_key(updateKey_.data(), keyBits, &aesKey) != 0)
    {
        Log("ERROR", "AES_set_decrypt_key failed");
        return {};
    }

    // Розпаковуємо весь wrappedData
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
    lastKeyChangeAlFragment_ = keyChangeAlFragment;


    // IEEE 1815-2012 Annex A, Table A-5 — plaintext у key wrap (AES-128, CD=16B):
    // [0:1]   = Key Length (uint16 LE) = 0x0010
    // [2:17]  = CDK  — Control Direction Session Key
    // [18:33] = MDK  — Monitoring Direction Session Key
    // [34:37] = KSQ  (4 байти LE)
    // [38:39] = USR  (2 байти LE)
    // [40]    = KWA
    // [41]    = Key Status
    // [42]    = MAL
    // [43:44] = CDL  (2 байти LE)
    // [45:60] = CD_OS — Challenge Data з нашого g120v5
    // [61:63] = Padding (3 байти)
    // MAC у plaintext ВІДСУТНІЙ — цілісність гарантує AES Key Wrap IV (RFC 3394)
    constexpr size_t KEY_LEN_OFFSET = 0;
    constexpr size_t CDK_OFFSET     = 2;
    constexpr size_t MDK_OFFSET     = 18;
    constexpr size_t CD_OS_OFFSET   = 45;

    const size_t cdLen = lastChallengeData.size(); // = 32
    const size_t minRequired = CD_OS_OFFSET + cdLen; // = 77

    if (unwrapped.size() < minRequired)
    {
        std::ostringstream oss;
        oss << "Unwrapped key too small: " << unwrapped.size()
            << ", need " << minRequired;
        Log("ERROR", oss.str());
        InvalidateKeys(keyChange.userNumber, KeyStatus::AUTH_FAIL);
        return false;
    }

    // Перевірка Key Length field
    uint16_t keyLen = static_cast<uint16_t>(unwrapped[KEY_LEN_OFFSET]) |
                      (static_cast<uint16_t>(unwrapped[KEY_LEN_OFFSET + 1]) << 8);
    if (keyLen != 16)
    {
        std::ostringstream oss;
        oss << "Unexpected key length in wrapped data: " << keyLen;
        Log("WARN", oss.str());
    }

    // Перевірка CD_OS — має збігатися з Challenge Data, що ми відправили в g120v5
    const uint8_t* cdOsPtr = unwrapped.data() + CD_OS_OFFSET;
    if (std::memcmp(cdOsPtr, lastChallengeData.data(), cdLen) != 0)
    {
        Log("ERROR", "CD_OS mismatch: key change rejected");
        InvalidateKeys(keyChange.userNumber, KeyStatus::AUTH_FAIL);
        return false;
    }
    Log("INFO", "CD_OS verification successful");

    // TODO: remove debug logging
    // DEBUG: log extracted CDK and MDK to verify key extraction offsets.
    // {
    //     std::ostringstream d;
    //     d << "DEBUG CDK (bytes 2-17): ";
    //     for (int i=0;i<16;i++) d<<std::hex<<std::setw(2)<<std::setfill('0')
    //         <<(unsigned)unwrapped[CDK_OFFSET+i]<<(i<15?":":"");
    //     Log("INFO", d.str());
    // }
    // {
    //     std::ostringstream d;
    //     d << "DEBUG MDK (bytes 18-33): ";
    //     for (int i=0;i<16;i++) d<<std::hex<<std::setw(2)<<std::setfill('0')
    //         <<(unsigned)unwrapped[MDK_OFFSET+i]<<(i<15?":":"");
    //     Log("INFO", d.str());
    // }

    // Витягуємо сесійні ключі з правильних зміщень
    controlKeyOut.fill(0);
    monitorKeyOut.fill(0);
    std::memcpy(controlKeyOut.data(), unwrapped.data() + CDK_OFFSET, 16); // CDK
    std::memcpy(monitorKeyOut.data(), unwrapped.data() + MDK_OFFSET, 16); // MDK

    userNumOut = keyChange.userNumber;
    keyStatusMap_[keyChange.userNumber] = KeyStatus::OK;

    std::ostringstream oss;
    oss << "Key Change successful: User=" << keyChange.userNumber
        << ", KSQ=" << keyChange.ksq;
    Log("INFO", oss.str());
    return true;
}
/*
std::vector<uint8_t> SAKeyManager::BuildKeyStatusConfirmation(
    uint16_t userNum,
    const std::array<uint8_t, 32>& monitorKey,
    MACAlgorithm macAlgo)
{
    // Generate NEW challenge data for the next authentication session.
    // Per IEEE 1815-2012 §7.5.5.3: the Key Status sent after Key Change
    // must contain fresh Challenge Data (not the one from the Key Change).
    //lastChallengeData = GenerateRandomChallengeData();
    // lastUserNum = userNum;

    uint8_t macAlgoVal = static_cast<uint8_t>(macAlgo);

    // Build MAC input per IEEE 1815-2012 Table A-6 (Key Status MAC input):
    //   KSQ(4) | USR(2) | KWA(1) | KeyStatus(1) | MAL(1) | CDL(2) | CD(N)
    std::vector<uint8_t> macInput;
    auto pushU32LE = [&](uint32_t v) {
        macInput.push_back( v        & 0xFF);
        macInput.push_back((v >>  8) & 0xFF);
        macInput.push_back((v >> 16) & 0xFF);
        macInput.push_back((v >> 24) & 0xFF);
    };
    auto pushU16LE = [&](uint16_t v) {
        macInput.push_back( v       & 0xFF);
        macInput.push_back((v >> 8) & 0xFF);
    };

    pushU32LE(ksq_);
    pushU16LE(userNum);
    macInput.push_back(static_cast<uint8_t>(keyWrapAlgo));
    macInput.push_back(static_cast<uint8_t>(KeyStatus::OK));
    macInput.push_back(macAlgoVal);
    pushU16LE(static_cast<uint16_t>(lastChallengeData.size()));
    macInput.insert(macInput.end(), lastChallengeData.begin(), lastChallengeData.end());
    //std::copy(lastChallengeData.begin(), lastChallengeData.end(), std::back_inserter(macInput));

    // Compute HMAC-SHA256, truncate to 16 bytes per master config
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digestLen = 0;
    HMAC(EVP_sha256(),
         monitorKey.data(), 16,           // use only first 16 bytes of 32-byte key slot
         macInput.data(),   macInput.size(),
         digest,            &digestLen);

    // Per IEEE 1815-2012 Table 7-5:
    //   MAL 0x02 = HMAC-SHA256 truncated to 8 octets
    //   MAL 0x03 = HMAC-SHA256 truncated to 16 octets (but many implementations treat as 8!)
    constexpr size_t  MAC_TRUNC_LEN = 8;         // truncate to 8 bytes
    std::vector<uint8_t> macValue;
    if (digestLen >= MAC_TRUNC_LEN)
        macValue.assign(digest, digest + MAC_TRUNC_LEN);
    else
        macValue.assign(digest, digest + digestLen); // safety fallback

    // Build g120v5 object — Group120Builder calculates size from
    // challengeData only; we must build the full serialized payload manually
    // so that the 2-byte size field in qualifier 0x5B covers CD + MAC.
    //
    // g120v5 payload structure (qualifier 0x5B, object size N):
    //   [0:3]  KSQ  (uint32 LE)
    //   [4:5]  USR  (uint16 LE)
    //   [6]    KWA
    //   [7]    Key Status
    //   [8]    MAL
    //   [9:10] CDL  (uint16 LE)
    //   [11 .. 11+CDL-1]  Challenge Data
    //   [11+CDL .. 11+CDL+macLen-1]  MAC Value
    const uint16_t cdl = static_cast<uint16_t>(lastChallengeData.size());
    const uint16_t objSize = static_cast<uint16_t>(4 + 2 + 1 + 1 + 1 + 2 + cdl + macValue.size());

    // DNP3 object header: Group(1) + Var(1) + Qualifier(1) + Count(1) + ObjSize(2)
    std::vector<uint8_t> result;
    result.reserve(6 + objSize);
    result.push_back(0x78);  // Group 120
    result.push_back(0x05);  // Variation 5
    result.push_back(0x5B);  // Qualifier: 16-bit free-format
    result.push_back(0x01);  // Count = 1
    result.push_back( objSize        & 0xFF);
    result.push_back((objSize >> 8)  & 0xFF);

    // Object payload
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

    appendU32LE(ksq_);                                          // KSQ
    appendU16LE(userNum);                                       // USR
    result.push_back(static_cast<uint8_t>(keyWrapAlgo));       // KWA
    result.push_back(static_cast<uint8_t>(KeyStatus::OK));      // Key Status = OK
    result.push_back(macAlgoVal);                               // MAL
    appendU16LE(cdl);                                           // CDL
    result.insert(result.end(), lastChallengeData.begin(), lastChallengeData.end()); // CD
    result.insert(result.end(), macValue.begin(), macValue.end());                     // MAC

    std::ostringstream oss;
    oss << "Key Status Confirmation: KSQ=" << ksq_
        << ", User=" << userNum
        << ", Status=OK, MAC=" << macValue.size() << " bytes"
        << ", CD=" << lastChallengeData.size() << " bytes";
    Log("INFO", oss.str());

    // TODO: remove debug log
    // DEBUG: log MDK, MAC input and computed MAC to verify HMAC correctness.
    // Remove after MAC verification is confirmed with master.
    {
        std::ostringstream dbg;
        dbg << "DEBUG MAC key (MDK, first 16 bytes): ";
        for (int i = 0; i < 16; ++i)
            dbg << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(monitorKey[i]) << (i<15?":":"");
        Log("INFO", dbg.str());
    }
    {
        std::ostringstream dbg;
        dbg << "DEBUG MAC input (" << macInput.size() << " bytes): ";
        for (size_t i = 0; i < macInput.size(); ++i)
            dbg << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(macInput[i]) << (i+1<macInput.size()?":":"");
        Log("INFO", dbg.str());
    }
    {
        std::ostringstream dbg;
        dbg << "DEBUG MAC output (" << macValue.size() << " bytes): ";
        for (size_t i = 0; i < macValue.size(); ++i)
            dbg << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(macValue[i]) << (i+1<macValue.size()?":":"");
        Log("INFO", dbg.str());
    }

    return result;
}
*/
std::vector<uint8_t> SAKeyManager::BuildKeyStatusConfirmation(
    uint16_t userNum,
    const std::array<uint8_t, 32>& monitorKey,
    MACAlgorithm macAlgo)
{
    // Per IEEE 1815-2012 Table A-4:
    // MAC input = the entire Application Layer fragment of the g120v6 Key Change
    // most recently received from the master. NOT the fields of this g120v5 object.
    if (lastKeyChangeAlFragment_.empty())
    {
        Log("ERROR", "BuildKeyStatusConfirmation: no Key Change AL fragment stored");
        return {};
    }

    // Wire-level constants per IEEE 1815-2012 Table 7-4 and Table 7-5
    constexpr uint8_t KWA_AES128_WIRE     = 0x01;
    constexpr uint8_t STATUS_OK_WIRE      = 0x01;
    constexpr uint8_t MAL_SHA256_8_WIRE   = 0x03;  // HMAC-SHA256 truncated to 8 octets
    constexpr size_t  MAC_TRUNC_LEN       = 8;

    // Compute HMAC-SHA256(MDK, AL_fragment), truncate to 8 bytes
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digestLen = 0;
    HMAC(EVP_sha256(),
         monitorKey.data(), 16,
         lastKeyChangeAlFragment_.data(), lastKeyChangeAlFragment_.size(),
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
    result.push_back(KWA_AES128_WIRE);
    result.push_back(STATUS_OK_WIRE);
    result.push_back(MAL_SHA256_8_WIRE);
    result.push_back( cdl       & 0xFF);
    result.push_back((cdl >> 8) & 0xFF);
    result.insert(result.end(), lastChallengeData.begin(), lastChallengeData.end());
    result.insert(result.end(), macValue.begin(), macValue.end());

    // DEBUG: log MAC input (AL fragment) and computed MAC
    // {
    //     std::ostringstream d;
    //     d << "Key Status Confirmation: KSQ=" << ksq << ", User=" << userNum
    //       << ", Status=OK, MAL=0x03 (HMAC-SHA256-8)"
    //       << ", MAC=" << macValue.size() << " bytes";
    //     Log("INFO", d.str());
    // }
    // {
    //     std::ostringstream d;
    //     d << "DEBUG MAC key (MDK first 16B): ";
    //     for (int i = 0; i < 16; ++i)
    //         d << std::hex << std::setw(2) << std::setfill('0')
    //           << (int)monitorKey[i] << (i < 15 ? ":" : "");
    //     Log("INFO", d.str());
    // }
    // {
    //     std::ostringstream d;
    //     d << "DEBUG MAC input = AL fragment of g120v6 (" << lastKeyChangeAlFragment_.size() << " bytes): ";
    //     for (size_t i = 0; i < lastKeyChangeAlFragment_.size(); ++i)
    //         d << std::hex << std::setw(2) << std::setfill('0')
    //           << (int)lastKeyChangeAlFragment_[i]
    //           << (i + 1 < lastKeyChangeAlFragment_.size() ? ":" : "");
    //     Log("INFO", d.str());
    // }
    // {
    //     std::ostringstream d;
    //     d << "DEBUG MAC output: ";
    //     for (size_t i = 0; i < macValue.size(); ++i)
    //         d << std::hex << std::setw(2) << std::setfill('0')
    //           << (int)macValue[i] << (i + 1 < macValue.size() ? ":" : "");
    //     Log("INFO", d.str());
    // }

    return result;
}

uint32_t SAKeyManager::GetKSQ() const
{
    return ksq;
}

KeyStatus SAKeyManager::GetKeyStatus(uint16_t userNum) const
{
    auto it = keyStatusMap_.find(userNum);
    if (it != keyStatusMap_.end())
    {
        return it->second;
    }
    
    // Default: keys not initialized
    return KeyStatus::NOT_INIT;
}

void SAKeyManager::InvalidateKeys(uint16_t userNum, KeyStatus status)
{
    keyStatusMap_[userNum] = status;

    std::ostringstream oss;
    oss << "Keys invalidated for user " << userNum 
        << ", status=" << static_cast<int>(status);
    Log("WARN", oss.str());
}

} // namespace opendnp3
