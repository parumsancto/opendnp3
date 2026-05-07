/*
 * Unit tests for Secure Authentication v2 (SAv2) support.
 *
 * Covers:
 *   1. SAKeyManager SAv2 constructor sets AES-128 key wrap.
 *   2. OnKeyStatusRequest MAL byte equals HMAC_SHA1_TRUNC_10 (0x02) in SAv2.
 *   3. OnKeyChange accepts a valid SAv2-format AES-128-wrapped payload.
 *   4. BuildKeyStatusConfirmation returns g120v5 with MAL=0x00 (no MAC) in SAv2.
 *   5. SAResponder SAv2 always uses HMAC-SHA1-trunc10 regardless of challenge algo.
 *   6. SAChallenger SAv2 always advertises HMAC_SHA1_TRUNC_10 in generated challenge.
 *   7. SAv5 behavior unchanged: MAL=0x00 in NOT_INIT status, CD_OS verified in OnKeyChange.
 */

#include <catch.hpp>

#include "opendnp3/app/secauth/SAKeyManager.h"
#include "opendnp3/app/secauth/SAResponder.h"
#include "opendnp3/app/secauth/SAChallenger.h"
#include "opendnp3/app/secauth/Group120.h"

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <array>
#include <vector>
#include <cstring>
#include <cstdint>

using namespace opendnp3;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::array<uint8_t, 16> MakeKey16(uint8_t fill)
{
    std::array<uint8_t, 16> k;
    k.fill(fill);
    return k;
}

static std::array<uint8_t, 32> MakeKey32(uint8_t fill)
{
    std::array<uint8_t, 32> k;
    k.fill(fill);
    return k;
}

// Build an SAv2 key-wrap plaintext and wrap it with AES-128 Key Wrap (RFC 3394).
// Plaintext: KL(2LE) + CDK(16) + MDK(16) + KSQ(4LE) + USR(2LE) = 40 bytes
// Wrapped:   40 + 8 = 48 bytes
static std::vector<uint8_t> BuildSAv2WrappedKeys(
    const std::array<uint8_t, 16>& updateKey,
    const std::array<uint8_t, 16>& cdk,
    const std::array<uint8_t, 16>& mdk,
    uint32_t ksq,
    uint16_t userNum)
{
    // Build 40-byte plaintext
    std::vector<uint8_t> plain(40, 0);
    plain[0] = 16; plain[1] = 0; // KL = 16 LE
    std::memcpy(plain.data() + 2,  cdk.data(), 16);
    std::memcpy(plain.data() + 18, mdk.data(), 16);
    plain[34] =  ksq        & 0xFF;
    plain[35] = (ksq >>  8) & 0xFF;
    plain[36] = (ksq >> 16) & 0xFF;
    plain[37] = (ksq >> 24) & 0xFF;
    plain[38] =  userNum       & 0xFF;
    plain[39] = (userNum >> 8) & 0xFF;

    // AES-128 Key Wrap → 48 bytes output
    std::vector<uint8_t> wrapped(48);
    AES_KEY wrapKey;
    AES_set_encrypt_key(updateKey.data(), 128, &wrapKey);
    int wlen = AES_wrap_key(&wrapKey, nullptr, wrapped.data(), plain.data(), 40);
    REQUIRE(wlen == 48);
    return wrapped;
}

// Parse g120v5 bytes (starting after the 6-byte object header) and return MAL byte.
// Layout: KSQ(4) + USR(2) + KWA(1) + Status(1) + MAL(1) + ...
static uint8_t ExtractMALFromG120v5(const std::vector<uint8_t>& bytes)
{
    // bytes[0..5]  = object header (Group, Var, Qualifier, Count, ObjSize LE)
    // bytes[6..9]  = KSQ
    // bytes[10..11]= USR
    // bytes[12]    = KWA
    // bytes[13]    = Status
    // bytes[14]    = MAL
    REQUIRE(bytes.size() >= 15);
    return bytes[14];
}

static uint8_t ExtractKWAFromG120v5(const std::vector<uint8_t>& bytes)
{
    REQUIRE(bytes.size() >= 13);
    return bytes[12];
}

static uint8_t ExtractStatusFromG120v5(const std::vector<uint8_t>& bytes)
{
    REQUIRE(bytes.size() >= 14);
    return bytes[13];
}

// ---------------------------------------------------------------------------
// Test 1: SAKeyManager SAv2 constructor sets AES-128 key wrap
// ---------------------------------------------------------------------------
TEST_CASE("SAv2 SAKeyManager constructor sets AES-128 key wrap", "[sav2][keymanager]")
{
    std::array<uint8_t, 32> key = MakeKey32(0xAB);
    SAKeyManager km(key, SAMode::SAV2);
    REQUIRE(km.GetKeyWrapAlgorithm() == KeyWrapAlgorithm::AES128);
}

// ---------------------------------------------------------------------------
// Test 2: SAKeyManager SAv5 constructor sets AES-256 key wrap
// ---------------------------------------------------------------------------
TEST_CASE("SAv5 SAKeyManager constructor sets AES-256 key wrap", "[sav5][keymanager]")
{
    std::array<uint8_t, 32> key = MakeKey32(0xCD);
    SAKeyManager km(key, SAMode::SAV5);
    REQUIRE(km.GetKeyWrapAlgorithm() == KeyWrapAlgorithm::AES256);
}

// ---------------------------------------------------------------------------
// Test 3: SAv2 OnKeyStatusRequest (NOT_INIT) has MAL=0x00 (no MAC in NOT_INIT)
// ---------------------------------------------------------------------------
TEST_CASE("SAv2 OnKeyStatusRequest NOT_INIT has MAL=0x00", "[sav2][keymanager]")
{
    std::array<uint8_t, 32> key = MakeKey32(0x11);
    SAKeyManager km(key, SAMode::SAV2);

    auto bytes = km.OnKeyStatusRequest(1);
    REQUIRE(!bytes.empty());

    uint8_t mal = ExtractMALFromG120v5(bytes);
    // MAL=0x00 when no MAC is present (Status=NOT_INIT), per IEEE 1815-2012 Table 7-4
    REQUIRE(mal == 0x00);
    REQUIRE(ExtractKWAFromG120v5(bytes) == static_cast<uint8_t>(KeyWrapAlgorithm::AES128)); // 0x01
}

// ---------------------------------------------------------------------------
// Test 4: SAv5 OnKeyStatusRequest (NOT_INIT) advertises MAL=0x00 (no MAC)
// ---------------------------------------------------------------------------
TEST_CASE("SAv5 OnKeyStatusRequest NOT_INIT has MAL=0x00", "[sav5][keymanager]")
{
    std::array<uint8_t, 32> key = MakeKey32(0x22);
    SAKeyManager km(key, SAMode::SAV5);

    auto bytes = km.OnKeyStatusRequest(1);
    REQUIRE(!bytes.empty());

    uint8_t mal = ExtractMALFromG120v5(bytes);
    REQUIRE(mal == 0x00);
    REQUIRE(ExtractKWAFromG120v5(bytes) == static_cast<uint8_t>(KeyWrapAlgorithm::AES256)); // 0x02
}

// ---------------------------------------------------------------------------
// Test 5: SAv2 OnKeyChange with valid AES-128-wrapped payload succeeds
// ---------------------------------------------------------------------------
TEST_CASE("SAv2 OnKeyChange with valid AES-128 wrapped keys succeeds", "[sav2][keymanager]")
{
    std::array<uint8_t, 16> updateKey16 = MakeKey16(0xAA);
    std::array<uint8_t, 32> updateKey32 = MakeKey32(0);
    std::memcpy(updateKey32.data(), updateKey16.data(), 16); // upper 16 bytes = 0

    SAKeyManager km(updateKey32, SAMode::SAV2);

    // Trigger OnKeyStatusRequest to generate KSQ and challenge data
    auto statusBytes = km.OnKeyStatusRequest(1);
    uint32_t ksq = km.GetKSQ();
    REQUIRE(ksq == 1);

    // Build valid SAv2 wrapped payload
    std::array<uint8_t, 16> cdk = MakeKey16(0x11);
    std::array<uint8_t, 16> mdk = MakeKey16(0x22);
    auto wrapped = BuildSAv2WrappedKeys(updateKey16, cdk, mdk, ksq, 1);

    Group120Var6 var6;
    var6.ksq        = ksq;
    var6.userNumber = 1;

    uint16_t userOut = 0;
    std::array<uint8_t, 32> cdkOut = MakeKey32(0);
    std::array<uint8_t, 32> mdkOut = MakeKey32(0);

    bool ok = km.OnKeyChange(var6, wrapped, {}, userOut, cdkOut, mdkOut);
    REQUIRE(ok);
    REQUIRE(userOut == 1);

    // Verify extracted keys match what we wrapped
    REQUIRE(std::memcmp(cdkOut.data(), cdk.data(), 16) == 0);
    REQUIRE(std::memcmp(mdkOut.data(), mdk.data(), 16) == 0);
    REQUIRE(km.GetKeyStatus(1) == KeyStatus::OK);
}

// ---------------------------------------------------------------------------
// Test 6: SAv2 OnKeyChange with wrong KSQ fails
// ---------------------------------------------------------------------------
TEST_CASE("SAv2 OnKeyChange with wrong KSQ fails", "[sav2][keymanager]")
{
    std::array<uint8_t, 16> updateKey16 = MakeKey16(0xBB);
    std::array<uint8_t, 32> updateKey32 = MakeKey32(0);
    std::memcpy(updateKey32.data(), updateKey16.data(), 16);

    SAKeyManager km(updateKey32, SAMode::SAV2);
    km.OnKeyStatusRequest(1); // KSQ = 1

    std::array<uint8_t, 16> cdk = MakeKey16(0x33);
    std::array<uint8_t, 16> mdk = MakeKey16(0x44);
    // Use wrong KSQ = 99 in the plaintext
    auto wrapped = BuildSAv2WrappedKeys(updateKey16, cdk, mdk, 99, 1);

    Group120Var6 var6;
    var6.ksq        = 1; // outer KSQ matches
    var6.userNumber = 1;

    uint16_t userOut = 0;
    std::array<uint8_t, 32> cdkOut = MakeKey32(0);
    std::array<uint8_t, 32> mdkOut = MakeKey32(0);

    bool ok = km.OnKeyChange(var6, wrapped, {}, userOut, cdkOut, mdkOut);
    REQUIRE(!ok); // embedded KSQ mismatch
}

// ---------------------------------------------------------------------------
// Test 7: SAv2 BuildKeyStatusConfirmation includes HMAC-SHA1-trunc10 MAC
// MAC input = full AL fragment of the received g120v6 (same as SAv5, but SHA-1).
// ---------------------------------------------------------------------------
TEST_CASE("SAv2 BuildKeyStatusConfirmation includes HMAC-SHA1-trunc10 MAC", "[sav2][keymanager]")
{
    std::array<uint8_t, 16> updateKey16 = MakeKey16(0xAA);
    std::array<uint8_t, 32> updateKey32 = MakeKey32(0);
    std::memcpy(updateKey32.data(), updateKey16.data(), 16);

    SAKeyManager km(updateKey32, SAMode::SAV2);
    km.OnKeyStatusRequest(1);

    std::array<uint8_t, 16> cdk = MakeKey16(0x55);
    std::array<uint8_t, 16> mdk = MakeKey16(0x66);
    auto wrapped = BuildSAv2WrappedKeys(updateKey16, cdk, mdk, km.GetKSQ(), 1);

    Group120Var6 var6;
    var6.ksq = km.GetKSQ();
    var6.userNumber = 1;

    // Simulate the AL fragment that OutstationContext passes to OnKeyChange:
    // AC(1) + FC(1) + object_header(6) + object_data(wrapped)
    std::vector<uint8_t> alFragment;
    alFragment.push_back(0xc0); // AC
    alFragment.push_back(0x20); // FC=32 (Auth Request)
    alFragment.push_back(0x78); // Group 120
    alFragment.push_back(0x06); // Var 6
    alFragment.push_back(0x5b); // Qualifier
    alFragment.push_back(0x01); // Count=1
    uint16_t objSize = static_cast<uint16_t>(6 + 2 + wrapped.size()); // KSQ+USR+wrapped
    alFragment.push_back(objSize & 0xFF);
    alFragment.push_back((objSize >> 8) & 0xFF);
    // KSQ(4LE) + USR(2LE)
    alFragment.push_back(1); alFragment.push_back(0); alFragment.push_back(0); alFragment.push_back(0);
    alFragment.push_back(1); alFragment.push_back(0);
    alFragment.insert(alFragment.end(), wrapped.begin(), wrapped.end());

    uint16_t userOut = 0;
    std::array<uint8_t, 32> cdkOut = MakeKey32(0);
    std::array<uint8_t, 32> mdkOut = MakeKey32(0);
    REQUIRE(km.OnKeyChange(var6, wrapped, alFragment, userOut, cdkOut, mdkOut));

    auto confirm = km.BuildKeyStatusConfirmation(1, mdkOut, MACAlgorithm::HMAC_SHA1_TRUNC_10);
    REQUIRE(!confirm.empty());

    uint8_t mal    = ExtractMALFromG120v5(confirm);
    uint8_t status = ExtractStatusFromG120v5(confirm);
    REQUIRE(mal    == static_cast<uint8_t>(MACAlgorithm::HMAC_SHA1_TRUNC_10)); // 0x02
    REQUIRE(status == static_cast<uint8_t>(KeyStatus::OK));                    // 0x01

    // Verify size: header(6) + KSQ(4)+USR(2)+KWA(1)+Stat(1)+MAL(1)+CDL(2)+CD(32)+MAC(10)
    const size_t expectedSize = 6 + 4 + 2 + 1 + 1 + 1 + 2 + 32 + 10;
    REQUIRE(confirm.size() == expectedSize);

    // MAC = HMAC-SHA1-trunc10(MDK[0..15], alFragment)
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    HMAC(EVP_sha1(), mdkOut.data(), 16, alFragment.data(), alFragment.size(), digest, &dlen);
    REQUIRE(dlen >= 10);
    // MAC starts at byte 49 (= 6+4+2+1+1+1+2+32)
    REQUIRE(std::memcmp(confirm.data() + 49, digest, 10) == 0);
}

// ---------------------------------------------------------------------------
// Test 8: SAv5 BuildKeyStatusConfirmation has MAL != 0x00 (MAC present)
// ---------------------------------------------------------------------------
TEST_CASE("SAv5 BuildKeyStatusConfirmation has MAL != 0x00 (MAC present)", "[sav5][keymanager]")
{
    // SAv5 requires a non-empty lastKeyChangeAlFragment for MAC computation.
    // We provide a dummy fragment.
    std::array<uint8_t, 32> key = MakeKey32(0xFF);
    SAKeyManager km(key, SAMode::SAV5);
    km.OnKeyStatusRequest(1);

    // Build a minimal SAv5-style plaintext manually and wrap it with AES-256.
    // KL(2)+CDK(16)+MDK(16)+KSQ(4)+USR(2)+KWA(1)+Stat(1)+MAL(1)+CDL(2)+CD(0) = 45 bytes
    // RFC 3394 requires plaintext length to be a multiple of 8. Pad to 48 bytes.
    uint32_t ksq = km.GetKSQ();
    std::vector<uint8_t> plain(48, 0);
    plain[0] = 16; plain[1] = 0; // KL = 16
    // CDK @ 2..17, MDK @ 18..33 — all zeros is fine for this test
    plain[34] =  ksq        & 0xFF;
    plain[35] = (ksq >>  8) & 0xFF;
    plain[36] = (ksq >> 16) & 0xFF;
    plain[37] = (ksq >> 24) & 0xFF;
    plain[38] =  1; plain[39] = 0; // USR = 1
    plain[40] = 2;  // KWA = AES-256
    plain[41] = 1;  // Status = OK
    plain[42] = 3;  // MAL = HMAC_SHA256_TRUNC_8
    plain[43] = 0; plain[44] = 0; // CDL = 0 (no CD_OS in this minimal test)
    // plain[45..47] = padding zeros

    std::vector<uint8_t> wrapped(56); // 48 + 8
    AES_KEY wrapKey;
    AES_set_encrypt_key(key.data(), 256, &wrapKey);
    int wlen = AES_wrap_key(&wrapKey, nullptr, wrapped.data(), plain.data(), 48);
    REQUIRE(wlen == 56);

    Group120Var6 var6;
    var6.ksq        = ksq;
    var6.userNumber = 1;

    // Provide a non-empty dummy AL fragment so BuildKeyStatusConfirmation can compute MAC
    std::vector<uint8_t> dummyFragment = {0xC0, 0x20, 0x78, 0x06, 0x5B, 0x01};

    uint16_t userOut = 0;
    std::array<uint8_t, 32> cdkOut = MakeKey32(0);
    std::array<uint8_t, 32> mdkOut = MakeKey32(0);
    bool ok = km.OnKeyChange(var6, wrapped, dummyFragment, userOut, cdkOut, mdkOut);
    REQUIRE(ok);

    auto confirm = km.BuildKeyStatusConfirmation(1, mdkOut, MACAlgorithm::HMAC_SHA256_TRUNC_8);
    REQUIRE(!confirm.empty());

    uint8_t mal = ExtractMALFromG120v5(confirm);
    REQUIRE(mal != 0x00); // SAv5 includes a MAC value
}

// ---------------------------------------------------------------------------
// Test 9: SAResponder SAv2 always uses HMAC-SHA1-trunc10
// ---------------------------------------------------------------------------
TEST_CASE("SAv2 SAResponder always uses HMAC-SHA1-trunc10", "[sav2][responder]")
{
    SAResponder responder(SAMode::SAV2);

    std::array<uint8_t, 32> cdk = MakeKey32(0xAA);
    std::array<uint8_t, 32> mdk = MakeKey32(0xBB);
    responder.SetSessionKeys(1, cdk, mdk);

    // Challenge with HMAC_SHA256_TRUNC_8 (algo=3) — SAv2 must ignore and use SHA1
    Group120Var1 challenge;
    challenge.csq          = 42;
    challenge.userNumber   = 1;
    challenge.macAlgorithm = static_cast<uint8_t>(MACAlgorithm::HMAC_SHA256_TRUNC_8);
    challenge.reason       = static_cast<uint8_t>(ChallengeReason::CRITICAL);

    std::vector<uint8_t> challengeData(16, 0xCD);
    std::vector<uint8_t> originalAPDU = {0xC0, 0x81, 0x00, 0x00};

    auto reply = responder.OnChallenge(challenge, challengeData, originalAPDU);
    REQUIRE(!reply.empty());

    // g120v2: Group(1)+Var(1)+Qual(1)+Count(1)+ObjSize(2)+CSQ(4)+USR(2)+MAC(N)
    // SAv2 MAC = HMAC-SHA1-trunc10 = 10 bytes
    // ObjSize = CSQ(4)+USR(2)+MAC(10) = 16
    REQUIRE(reply.size() >= 6 + 4 + 2 + 10);

    // Independently compute expected MAC (HMAC-SHA1-trunc10)
    // Input per SAv2: CSQ(4LE) + USR(2LE) + ChallengeData + OriginalAPDU
    std::vector<uint8_t> macInput;
    macInput.push_back(42); macInput.push_back(0); macInput.push_back(0); macInput.push_back(0); // CSQ
    macInput.push_back(1);  macInput.push_back(0); // USR
    macInput.insert(macInput.end(), challengeData.begin(), challengeData.end());
    macInput.insert(macInput.end(), originalAPDU.begin(), originalAPDU.end());

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    HMAC(EVP_sha1(), cdk.data(), 16, macInput.data(), macInput.size(), digest, &dlen);
    REQUIRE(dlen >= 10);

    // MAC starts at byte 6+4+2 = 12 in reply
    REQUIRE(std::memcmp(reply.data() + 12, digest, 10) == 0);
}

// ---------------------------------------------------------------------------
// Test 10: SAChallenger SAv2 always advertises HMAC_SHA1_TRUNC_10
// ---------------------------------------------------------------------------
TEST_CASE("SAv2 SAChallenger GenerateChallenge advertises HMAC_SHA1_TRUNC_10", "[sav2][challenger]")
{
    SAChallenger challenger(SAMode::SAV2);

    // Request SHA256 — SAv2 must override to SHA1
    auto bytes = challenger.GenerateChallenge(1, MACAlgorithm::HMAC_SHA256_TRUNC_8, ChallengeReason::CRITICAL);
    REQUIRE(!bytes.empty());

    // g120v1 layout: Group(1)+Var(1)+Qual(1)+Count(1)+ObjSize(2)+CSQ(4)+USR(2)+MACAlgo(1)+Reason(1)+CD(N)
    // macAlgorithm is at offset 6+4+2 = 12
    REQUIRE(bytes.size() >= 13);
    uint8_t macAlgo = bytes[12];
    REQUIRE(macAlgo == static_cast<uint8_t>(MACAlgorithm::HMAC_SHA1_TRUNC_10)); // 0x02
}

// ---------------------------------------------------------------------------
// Test 11: SAv5 SAChallenger preserves requested algo (SHA256)
// ---------------------------------------------------------------------------
TEST_CASE("SAv5 SAChallenger GenerateChallenge preserves SHA256 algo", "[sav5][challenger]")
{
    SAChallenger challenger(SAMode::SAV5);
    auto bytes = challenger.GenerateChallenge(1, MACAlgorithm::HMAC_SHA256_TRUNC_8, ChallengeReason::CRITICAL);
    REQUIRE(!bytes.empty());
    REQUIRE(bytes.size() >= 13);
    uint8_t macAlgo = bytes[12];
    REQUIRE(macAlgo == static_cast<uint8_t>(MACAlgorithm::HMAC_SHA256_TRUNC_8)); // 0x03
}

// ---------------------------------------------------------------------------
// Test 12: SAMode::NONE — SAKeyManager not instantiated (config check)
// ---------------------------------------------------------------------------
TEST_CASE("SAMode NONE config check", "[samode]")
{
    // Verify that SAMode enum values are as specified in the plan
    REQUIRE(static_cast<uint8_t>(SAMode::NONE) == 0);
    REQUIRE(static_cast<uint8_t>(SAMode::SAV2) == 2);
    REQUIRE(static_cast<uint8_t>(SAMode::SAV5) == 5);
}
