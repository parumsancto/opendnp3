/*
 * Copyright 2013-2022 Step Function I/O, LLC
 *
 * Licensed to Green Energy Corp (www.greenenergycorp.com) and Step Function I/O
 * LLC (https://stepfunc.io) under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Green Energy Corp and Step Function I/O LLC license
 * this file to you under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "OutstationContext.h"

#include "app/APDUBuilders.h"
#include "app/APDULogging.h"
#include "app/Functions.h"
#include "app/parsing/APDUHeaderParser.h"
#include "app/parsing/APDUParser.h"
#include "logging/LogMacros.h"
#include "outstation/AssignClassHandler.h"
#include "outstation/ClassBasedRequestHandler.h"
#include "outstation/CommandActionAdapter.h"
#include "outstation/CommandResponseHandler.h"
#include "outstation/ConstantCommandAction.h"
#include "outstation/FreezeRequestHandler.h"
#include "outstation/IINHelpers.h"
#include "outstation/ReadHandler.h"
#include "outstation/WriteHandler.h"

// ============================================================
// SAv5 INTEGRATION: Include Group120 parsing
// ============================================================
#include "opendnp3/app/secauth/Group120Parser.h"

#include "opendnp3/logging/LogLevels.h"

#include <openssl/hmac.h>
#include <cstring>

namespace opendnp3
{

OContext::OContext(const Addresses& addresses,
                   const OutstationConfig& config,
                   const DatabaseConfig& db_config,
                   const Logger& logger,
                   const std::shared_ptr<exe4cpp::IExecutor>& executor,
                   std::shared_ptr<ILowerLayer> lower,
                   std::shared_ptr<ICommandHandler> commandHandler,
                   std::shared_ptr<IOutstationApplication> application)
    :
      addresses(addresses),
      logger(logger),
      executor(executor),
      lower(std::move(lower)),
      commandHandler(std::move(commandHandler)),
      application(std::move(application)),
      eventBuffer(config.eventBufferConfig),
      database(db_config, eventBuffer, *this->application, config.params.typesAllowedInClass0),
      rspContext(database, eventBuffer),
      params(config.params),
      isOnline(false),
      isTransmitting(false),
      staticIIN(IINBit::DEVICE_RESTART),
      deferred(config.params.maxRxFragSize),
      sol(config.params.maxTxFragSize),
      unsol(config.params.maxTxFragSize),
      unsolRetries(config.params.numUnsolRetries),
      shouldCheckForUnsolicited(false),
      // ============================================================
      // SAv5 INTEGRATION: Initialize SA components if enabled
      // ============================================================
      saMode(config.params.saMode),
      pendingCriticalUserNum(0)
{
    // Initialize Secure Authentication components if enabled
    if (saMode != SAMode::NONE)
    {
        // Check if Update Key is configured (non-zero)
        bool hasUpdateKey = false;
        for (size_t i = 0; i < config.params.saUpdateKey.size(); ++i)
        {
            if (config.params.saUpdateKey[i] != 0)
            {
                hasUpdateKey = true;
                break;
            }
        }

        if (hasUpdateKey)
        {
            FORMAT_LOG_BLOCK(this->logger, flags::INFO,
                "Initializing SA components (mode=%s)",
                (saMode == SAMode::SAV2) ? "SAv2" : "SAv5");

            // Create SAKeyManager with Update Key and SA mode
            saKeyManager = std::unique_ptr<SAKeyManager>(new SAKeyManager(config.params.saUpdateKey, saMode));

            // Set logging callback for SAKeyManager
            auto keyMgrLogCallback = [this](const char* severity, const std::string& message) {
                if (std::string(severity) == "ERROR")
                {
                    FORMAT_LOG_BLOCK(this->logger, flags::ERR, "SAKeyManager: %s", message.c_str());
                }
                else if (std::string(severity) == "WARN")
                {
                    FORMAT_LOG_BLOCK(this->logger, flags::WARN, "SAKeyManager: %s", message.c_str());
                }
                else
                {
                    FORMAT_LOG_BLOCK(this->logger, flags::INFO, "SAKeyManager: %s", message.c_str());
                }
            };
            saKeyManager->SetLogCallback(keyMgrLogCallback);

            // Create SAResponder with SA mode
            saResponder = std::unique_ptr<SAResponder>(new SAResponder(saMode));

            // Set logging callback for SAResponder
            auto responderLogCallback = [this](const char* severity, const std::string& message) {
                if (std::string(severity) == "ERROR")
                {
                    FORMAT_LOG_BLOCK(this->logger, flags::ERR, "SAResponder: %s", message.c_str());
                }
                else if (std::string(severity) == "WARN")
                {
                    FORMAT_LOG_BLOCK(this->logger, flags::WARN, "SAResponder: %s", message.c_str());
                }
                else
                {
                    FORMAT_LOG_BLOCK(this->logger, flags::INFO, "SAResponder: %s", message.c_str());
                }
            };
            saResponder->SetLogCallback(responderLogCallback);

            // Create SAChallenger with SA mode
            saChallenger = std::unique_ptr<SAChallenger>(new SAChallenger(saMode));

            // Set logging callback for SAChallenger
            auto challengerLogCallback = [this](const char* severity, const std::string& message) {
                if (std::string(severity) == "ERROR")
                {
                    FORMAT_LOG_BLOCK(this->logger, flags::ERR, "SAChallenger: %s", message.c_str());
                }
                else if (std::string(severity) == "WARN")
                {
                    FORMAT_LOG_BLOCK(this->logger, flags::WARN, "SAChallenger: %s", message.c_str());
                }
                else
                {
                    FORMAT_LOG_BLOCK(this->logger, flags::INFO, "SAChallenger: %s", message.c_str());
                }
            };
            saChallenger->SetLogCallback(challengerLogCallback);

            SIMPLE_LOG_BLOCK(this->logger, flags::INFO, "SA components initialized successfully");
        }
        else
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::WARN,
                             "SAv5 enabled but saUpdateKey is all zeros - SA will not function");
            saMode = SAMode::NONE;
        }
    }
}

bool OContext::OnLowerLayerUp()
{
    if (isOnline)
    {
        SIMPLE_LOG_BLOCK(logger, flags::ERR, "already online");
        return false;
    }

    isOnline = true;
    this->shouldCheckForUnsolicited = true;

    // Reset application sequence number on each new TCP connection.
    // Without this, sol.seq.num accumulates across reconnects and
    // master rejects responses with unexpected SEQ values.
    this->sol.seq.num = AppSeqNum(0);

    // ============================================================
    // SAv5 INTEGRATION: Reset SA state on link up
    // ============================================================
    if (saMode != SAMode::NONE && saKeyManager)
    {
        // Clear pending critical APDU
        pendingCriticalAPDU.clear();
        pendingChallengeAPDU.clear();
        pendingCriticalUserNum = 0;
        pendingAuthenticatedReady = false;
        saUnsolBlocked_ = false;

        // Reset exchange flag on each new connection.
        saKeyExchangeInProgress = (saMode != SAMode::NONE);

        SIMPLE_LOG_BLOCK(this->logger, flags::INFO, "SA state reset on link up");
    }

    this->CheckForTaskStart();
    return true;
}

bool OContext::OnLowerLayerDown()
{
    if (!isOnline)
    {
        SIMPLE_LOG_BLOCK(logger, flags::ERR, "already offline");
        return false;
    }

    this->state = &StateIdle::Inst();

    isOnline = false;
    isTransmitting = false;

    sol.Reset();
    unsol.Reset();
    history.Reset();
    deferred.Reset();
    eventBuffer.Unselect();
    rspContext.Reset();
    confirmTimer.cancel();

    // ============================================================
    // SAv5 INTEGRATION: Invalidate keys on link down
    // ============================================================
    if (saMode != SAMode::NONE && saKeyManager)
    {
        // Invalidate all session keys (communication failure)
        // Iterate through potential user numbers (typically 1-65535)
        // For production, track active users instead
        for (uint16_t user = 1; user <= 10; ++user) // Assume max 10 users for now
        {
            if (saKeyManager->GetKeyStatus(user) == KeyStatus::OK)
            {
                saKeyManager->InvalidateKeys(user, KeyStatus::NOT_INIT);
            }
        }

        pendingCriticalAPDU.clear();
        pendingChallengeAPDU.clear();
        pendingCriticalUserNum = 0;
        pendingAuthenticatedReady = false;
        sessionControlKeys.clear();
        sessionMonitorKeys.clear();
        saKeyExchangeInProgress = false;
        saUnsolBlocked_ = false;
        awaitingKeyExchangeAfterReply = false;
        keyExchangeWaitTimer_.cancel();
        executingAuthenticatedAPDU = false;
        saSeqNum_ = 0;
        saPendingResponse_ = false;
        saPendingResponseLen_ = 0;

        SIMPLE_LOG_BLOCK(this->logger, flags::WARN, "SAv5 session keys invalidated due to link down");
    }

    return true;
}

bool OContext::OnTxReady()
{
    if (!isOnline || !isTransmitting)
    {
        return false;
    }

    this->isTransmitting = false;

    // Drain any SA response (g120v5 or g120v1) that was buffered because isTransmitting
    // was true when AUTH_REQUEST (g120v4) arrived. Send it now before any deferred
    // solicited request so the master's key exchange completes in the correct order.
    if (saPendingResponse_)
    {
        saPendingResponse_ = false;
        const ser4cpp::rseq_t txData(saTxBuffer_.data(),
                                     static_cast<uint32_t>(saPendingResponseLen_));
        this->BeginTx(this->addresses.destination, txData);
        return true;
    }

    this->CheckForTaskStart();
    return true;
}

bool OContext::OnReceive(const Message& message)
{
    if (!this->isOnline)
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "ignoring received data while offline");
        return false;
    }

    this->ProcessMessage(message);

    // Do not call CheckForTaskStart while SA Key Exchange is in progress.
    // Using a dedicated flag instead of checking KeyStatus, because KeyStatus
    // transitions to OK immediately after BuildKeyStatusConfirmation — before
    // the master has verified the confirmation MAC. Calling CheckForTaskStart
    // at that point triggers unsolicited transmission, which causes the master
    // to abort the Key Change (IEEE 1815-2012 Table 7-13 event 9).
    if (saMode == SAMode::NONE || !saKeyExchangeInProgress)
    {
        this->CheckForTaskStart();
    }

    return true;
}

// ============================================================
// SAv5 INTEGRATION: Critical function detection
// ============================================================

bool OContext::IsCriticalFunction(FunctionCode fc) const
{
    // IEEE 1815-2012 Table 7-1: Critical functions requiring authentication
    switch (fc)
    {
    case FunctionCode::WRITE:
    case FunctionCode::SELECT:
    case FunctionCode::OPERATE:
    case FunctionCode::DIRECT_OPERATE:
    case FunctionCode::DIRECT_OPERATE_NR:
    case FunctionCode::COLD_RESTART:
    case FunctionCode::WARM_RESTART:
    case FunctionCode::ENABLE_UNSOLICITED:
    case FunctionCode::DISABLE_UNSOLICITED:
    case FunctionCode::ASSIGN_CLASS:
        return true;
    default:
        return false;
    }
}

// ============================================================
// SAv5 INTEGRATION: Challenge initiation for critical functions
// ============================================================


bool OContext::InitiateChallengeForCriticalFunction(const ParsedRequest& request)
{
    if (saMode == SAMode::NONE || !saChallenger || !saResponder)
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::WARN, "Cannot initiate challenge - SA not enabled");
        return false;
    }

    // If a challenge is already in progress, retransmit the existing g120v1 rather than
    // generating a new one — a new CSQ would desync the master's expected reply.
    if (!pendingCriticalAPDU.empty() && !pendingChallengeAPDU.empty())
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::WARN,
            "Repeat critical request while challenge pending — retransmitting g120v1");
        const size_t retxLen = pendingChallengeAPDU.size();
        if (retxLen <= SA_TX_BUFFER_SIZE)
        {
            std::memcpy(saTxBuffer_.data(), pendingChallengeAPDU.data(), retxLen);
            if (this->isTransmitting)
            {
                saPendingResponseLen_ = retxLen;
                saPendingResponse_    = true;
            }
            else
            {
                const ser4cpp::rseq_t txData(saTxBuffer_.data(),
                                             static_cast<uint32_t>(retxLen));
                this->BeginTx(this->addresses.destination, txData);
            }
        }
        return true;
    }

    // Store FULL Application Layer fragment: [AppCtrl][FC][objects...]
    // MAC input per IEEE 1815-2012 Table 7-9 requires the complete AL fragment,
    // not just the objects portion that request.objects points to.
    pendingCriticalAPDU.clear();
    pendingCriticalAddresses = request.addresses;

    uint8_t alCtrl = 0;
    if (request.header.control.FIR) alCtrl |= 0x80;
    if (request.header.control.FIN) alCtrl |= 0x40;
    if (request.header.control.CON) alCtrl |= 0x20;
    if (request.header.control.UNS) alCtrl |= 0x10;
    alCtrl |= static_cast<uint8_t>(request.header.control.SEQ) & 0x0F;

    pendingCriticalAPDU.push_back(alCtrl);
    pendingCriticalAPDU.push_back(static_cast<uint8_t>(request.header.function));

    const uint8_t* dataPtr = static_cast<const uint8_t*>(request.objects);
    pendingCriticalAPDU.insert(pendingCriticalAPDU.end(),
        dataPtr,
        dataPtr + request.objects.length()
    );

    pendingCriticalUserNum = 1;

    // SAv2 mandates HMAC-SHA1-trunc10; SAChallenger will enforce this internally,
    // but we pass the correct default here for clarity and logging correctness.
    const MACAlgorithm challengeAlgo = (saMode == SAMode::SAV2)
        ? MACAlgorithm::HMAC_SHA1_TRUNC_10
        : MACAlgorithm::HMAC_SHA256_TRUNC_8;

    std::vector<uint8_t> challengeBytes = saChallenger->GenerateChallenge(
        static_cast<uint16_t>(pendingCriticalUserNum),
        challengeAlgo,
        ChallengeReason::CRITICAL
    );

    if (challengeBytes.empty())
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "Failed to generate challenge");
        pendingCriticalAPDU.clear();
        pendingCriticalAddresses = request.addresses;
        return false;
    }

    // FIX 1: Use saSeqNum_ — do not write sol.seq.num here.
    this->saSeqNum_ = static_cast<uint8_t>(request.header.control.SEQ);

    SendChallengeMessage(challengeBytes);

    FORMAT_LOG_BLOCK(this->logger, flags::INFO, "Challenge initiated for critical function: %s",
                     FunctionCodeSpec::to_human_string(request.header.function));

    return true;
}

// ============================================================
// SAv5 INTEGRATION: Send g120v5 Key Status response
// ============================================================

void OContext::SendKeyStatusResponse(uint16_t userNum,
                                     const std::vector<uint8_t>& keyStatusBytes)
{
    // Build 4-byte APDU header directly into saTxBuffer_ without touching
    // sol.tx.Start(), which would corrupt sol.tx.GetLastResponse() (a VIEW, not a copy).
    const IINField dynIIN = this->GetDynamicIIN();
    saTxBuffer_[0] = 0xC0u | (this->saSeqNum_ & 0x0Fu);                           // AppCtrl (FIX 1)
    saTxBuffer_[1] = static_cast<uint8_t>(FunctionCode::AUTH_RESPONSE);           // 0x83
    saTxBuffer_[2] = dynIIN.LSB;                                                   // IIN1
    saTxBuffer_[3] = dynIIN.MSB;                                                   // IIN2
    const size_t headerLen = 4;

    const size_t totalLen = headerLen + keyStatusBytes.size();
    if (totalLen > SA_TX_BUFFER_SIZE)
    {
        FORMAT_LOG_BLOCK(this->logger, flags::ERR,
                         "g120v5 Key Status for user %u exceeds SA_TX_BUFFER_SIZE",
                         userNum);
        return;
    }


    std::memcpy(saTxBuffer_.data() + headerLen,
                keyStatusBytes.data(),
                keyStatusBytes.size());

    if (this->isTransmitting)
    {
        // Buffer response — will be sent in OnTxReady once current TX completes.
        saPendingResponseLen_ = totalLen;
        saPendingResponse_ = true;
    }
    else
    {
        const ser4cpp::rseq_t txData(saTxBuffer_.data(),
                                     static_cast<uint32_t>(totalLen));
        this->BeginTx(this->addresses.destination, txData);
    }

    FORMAT_LOG_BLOCK(this->logger, flags::INFO,
                     "Sent g120v5 Key Status for user %u", userNum);
}

// ============================================================
// SAv5 INTEGRATION: Send g120v1 Challenge
// ============================================================

void OContext::SendChallengeMessage(const std::vector<uint8_t>& challengeBytes)
{
    // Build 4-byte APDU header directly into saTxBuffer_ without touching
    // sol.tx.Start(), which would corrupt sol.tx.GetLastResponse() (a VIEW, not a copy).
    const IINField dynIIN = this->GetDynamicIIN();
    saTxBuffer_[0] = 0xC0u | (this->saSeqNum_ & 0x0Fu);                           // AppCtrl (FIX 1)
    saTxBuffer_[1] = static_cast<uint8_t>(FunctionCode::AUTH_RESPONSE);           // 0x83
    saTxBuffer_[2] = dynIIN.LSB;                                                   // IIN1
    saTxBuffer_[3] = dynIIN.MSB;                                                   // IIN2
    const size_t headerLen = 4;

    const size_t totalLen = headerLen + challengeBytes.size();
    if (totalLen > SA_TX_BUFFER_SIZE)
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::ERR,
                         "g120v1 Challenge exceeds SA_TX_BUFFER_SIZE - not sent");
        return;
    }


    std::memcpy(saTxBuffer_.data() + headerLen,
                challengeBytes.data(),
                challengeBytes.size());

    // Store complete challenge AL fragment for MAC input (IEEE 1815-2012 Table A-3).
    pendingChallengeAPDU.assign(saTxBuffer_.data(), saTxBuffer_.data() + totalLen);

    if (this->isTransmitting)
    {
        // Buffer response — will be sent in OnTxReady once current TX completes.
        saPendingResponseLen_ = totalLen;
        saPendingResponse_ = true;
    }
    else
    {
        // AUTH_RESPONSE is never retransmitted (CON=0): bypass BeginResponseTx / sol.tx.Record.
        const ser4cpp::rseq_t txData(saTxBuffer_.data(),
                                     static_cast<uint32_t>(totalLen));
        this->BeginTx(this->addresses.destination, txData);
    }

    SIMPLE_LOG_BLOCK(this->logger, flags::INFO, "Sent g120v1 Challenge");
}

// ============================================================
// SAv5 INTEGRATION: Execute pending critical APDU
// ============================================================

bool OContext::TryHandleAggressiveMode(const ParsedRequest& request)
{
    const uint8_t* objData = static_cast<const uint8_t*>(request.objects);
    const size_t   objLen  = request.objects.length();

    // Detect g120v3: Group=0x78, Variation=0x03
    if (objLen < 3 || objData[0] != 0x78 || objData[1] != 0x03)
        return false;

    // Parse DNP3 object header to find payload bounds
    const uint8_t qualifier = objData[2];
    size_t g3HeaderLen  = 0;
    size_t g3PayloadLen = 0;

    if (qualifier == 0x5B)  // 16-bit Free-Format
    {
        if (objLen < 6) return false;
        const uint16_t sz = static_cast<uint16_t>(objData[4])
                          | (static_cast<uint16_t>(objData[5]) << 8);
        g3HeaderLen  = 6;
        g3PayloadLen = static_cast<size_t>(sz);
    }
    else if (qualifier == 0x07)  // 1-byte Count
    {
        if (objLen < 4) return false;
        g3HeaderLen  = 4;
        // GeoSCADA SAv2: payload is CSQ(4)+USR(2) only
        g3PayloadLen = sizeof(Group120Var3);  // 6 bytes
    }
    else
    {
        return false;
    }

    if (g3PayloadLen < sizeof(Group120Var3) || g3HeaderLen + g3PayloadLen > objLen)
        return false;

    // Parse fixed fields
    const uint8_t* g3Payload = objData + g3HeaderLen;
    Group120Var3 var3;
    var3.csq        = static_cast<uint32_t>(g3Payload[0])
                    | (static_cast<uint32_t>(g3Payload[1]) <<  8)
                    | (static_cast<uint32_t>(g3Payload[2]) << 16)
                    | (static_cast<uint32_t>(g3Payload[3]) << 24);
    var3.userNumber = static_cast<uint16_t>(g3Payload[4])
                    | (static_cast<uint16_t>(g3Payload[5]) <<  8);

    // Extract optional MAC value (bytes after fixed CSQ+USR in g120v3 payload)
    const size_t macBytesOffset = sizeof(Group120Var3);  // 6
    const bool   hasMac         = (g3PayloadLen > macBytesOffset);
    std::vector<uint8_t> receivedMAC;
    if (hasMac)
        receivedMAC.assign(g3Payload + macBytesOffset, g3Payload + g3PayloadLen);

    const size_t g3TotalSize = g3HeaderLen + g3PayloadLen;

    // Scan for g120v9 (HMAC) at ANY position after g120v3.
    // GeoSCADA SAv2 format: [g120v3][protected_objects][g120v9]
    // — g120v9 is at the END, not immediately after g120v3.
    std::vector<uint8_t> aggressiveMAC;
    size_t g9Offset    = 0;
    size_t g9TotalSize = 0;
    bool hasG9 = false;

    for (size_t pos = g3TotalSize; pos + 2 < objLen && !hasG9; ++pos)
    {
        if (objData[pos] != 0x78 || objData[pos + 1] != 0x09)
            continue;
        const uint8_t g9Qual = objData[pos + 2];
        if (g9Qual == 0x5B && pos + 6 <= objLen)
        {
            const uint16_t macSize = static_cast<uint16_t>(objData[pos + 4])
                                   | (static_cast<uint16_t>(objData[pos + 5]) << 8);
            const size_t macStart = pos + 6;
            if (macStart + macSize <= objLen)
            {
                aggressiveMAC.assign(objData + macStart, objData + macStart + macSize);
                g9Offset    = pos;
                g9TotalSize = 6 + static_cast<size_t>(macSize);
                hasG9 = true;
                SIMPLE_LOG_BLOCK(this->logger, flags::INFO, "g120v9 HMAC object found");
            }
        }
        else if (g9Qual == 0x07 && pos + 4 <= objLen)
        {
            const size_t expectedMacLen = (saMode == SAMode::SAV2) ? 10u : 8u;
            const size_t macStart = pos + 4;
            if (macStart + expectedMacLen <= objLen)
            {
                aggressiveMAC.assign(objData + macStart, objData + macStart + expectedMacLen);
                g9Offset    = pos;
                g9TotalSize = 4 + expectedMacLen;
                hasG9 = true;
                SIMPLE_LOG_BLOCK(this->logger, flags::INFO, "g120v9 HMAC object found");
            }
        }
    }

    FORMAT_LOG_BLOCK(this->logger, flags::INFO,
        "g120v3 Aggressive Mode: CSQ=%u, User=%u",
        static_cast<unsigned>(var3.csq), static_cast<unsigned>(var3.userNumber));

    const uint16_t userNum = var3.userNumber;

    // Session keys must be valid to use Aggressive Mode
    if (!saKeyManager || saKeyManager->GetKeyStatus(userNum) != KeyStatus::OK)
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN,
            "Aggressive Mode: keys not OK for user %u — falling back to challenge",
            static_cast<unsigned>(userNum));
        return false;
    }

    auto keyIt = sessionControlKeys.find(userNum);
    if (keyIt == sessionControlKeys.end())
    {
        FORMAT_LOG_BLOCK(this->logger, flags::ERR,
            "Aggressive Mode: no CDSK for user %u", static_cast<unsigned>(userNum));
        saKeyManager->InvalidateKeys(userNum, KeyStatus::AUTH_FAIL);
        return false;
    }
    const std::array<uint8_t, 32>& controlKey = keyIt->second;

    // MAC verification (per IEEE 1815-2012 Table A-3)
    if (hasG9 || hasMac)
    {
        const std::vector<uint8_t>& macToValidate = hasG9 ? aggressiveMAC : receivedMAC;

        // Reconstruct AppCtrl from parsed control fields.
        uint8_t alCtrl = 0;
        if (request.header.control.FIR) alCtrl |= 0x80;
        if (request.header.control.FIN) alCtrl |= 0x40;
        if (request.header.control.CON) alCtrl |= 0x20;
        if (request.header.control.UNS) alCtrl |= 0x10;
        alCtrl |= static_cast<uint8_t>(request.header.control.SEQ) & 0x0F;

        // Per SAv5 Annex A Table A-9 (and SAv2 §3.1, deferring to the Group 120 library):
        // MAC input = (full AL fragment of latest g120v1 Challenge)
        //           || (full AL fragment of this Aggressive Mode request, with ONLY the
        //               g120v9 MAC value bytes excluded — the g120v9 object header and
        //               prefix MUST be included)
        std::vector<uint8_t> macInput;
        macInput.reserve(pendingChallengeAPDU.size() + 2 + objLen);
        macInput.insert(macInput.end(), pendingChallengeAPDU.begin(), pendingChallengeAPDU.end());
        macInput.push_back(alCtrl);
        macInput.push_back(static_cast<uint8_t>(request.header.function));
        if (hasG9)
        {
            // g9TotalSize = (header+prefix) + (MAC value).  aggressiveMAC.size() = MAC value bytes.
            // So the g9 header+prefix length is the difference.
            const size_t g9HeaderPrefixSize = g9TotalSize - aggressiveMAC.size();
            const size_t macValueStart      = g9Offset + g9HeaderPrefixSize;
            const size_t macValueEnd        = g9Offset + g9TotalSize;

            // Include all bytes up to (but not including) the MAC value bytes.
            // This includes g120v3, all protected objects, AND g120v9's header+prefix.
            macInput.insert(macInput.end(), objData, objData + macValueStart);
            // Include any bytes that follow the MAC value (typically empty when g120v9 is last).
            macInput.insert(macInput.end(), objData + macValueEnd, objData + objLen);
        }
        else
        {
            // Legacy MAC-embedded-in-g120v3 layout: include g120v3 header + CSQ+USR fields,
            // exclude the MAC bytes inside g120v3, include any following objects.
            macInput.insert(macInput.end(), objData, objData + g3HeaderLen + macBytesOffset);
            macInput.insert(macInput.end(), objData + g3TotalSize, objData + objLen);
        }

        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int  digestLen = 0;
        const int keyLen = static_cast<int>(saKeyManager->GetSessionKeyLen());
        size_t truncLen = 0;

        if (saMode == SAMode::SAV2)
        {
            HMAC(EVP_sha1(), controlKey.data(), std::min(keyLen, 16),
                 macInput.data(), macInput.size(), digest, &digestLen);
            truncLen = 10;
        }
        else
        {
            HMAC(EVP_sha256(), controlKey.data(), keyLen,
                 macInput.data(), macInput.size(), digest, &digestLen);
            truncLen = 8;
        }

        const size_t expectedLen = std::min(static_cast<size_t>(digestLen), truncLen);
        if (macToValidate.size() != expectedLen ||
            std::memcmp(digest, macToValidate.data(), expectedLen) != 0)
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::ERR,
                "Aggressive Mode: MAC validation FAILED — invalidating keys");
            saKeyManager->InvalidateKeys(userNum, KeyStatus::AUTH_FAIL);
            return true;
        }
        SIMPLE_LOG_BLOCK(this->logger, flags::INFO, "Aggressive Mode: MAC verified");
    }

    FORMAT_LOG_BLOCK(this->logger, flags::INFO,
        "Aggressive Mode: accepted for user %u — executing WRITE directly",
        static_cast<unsigned>(userNum));

    // Build stripped objects: g120v3 removed, g120v9 removed at its actual position.
    std::vector<uint8_t> strippedBuf;
    if (hasG9)
    {
        strippedBuf.insert(strippedBuf.end(), objData + g3TotalSize, objData + g9Offset);
        strippedBuf.insert(strippedBuf.end(), objData + g9Offset + g9TotalSize, objData + objLen);
    }
    else
    {
        strippedBuf.insert(strippedBuf.end(), objData + g3TotalSize, objData + objLen);
    }
    ser4cpp::rseq_t strippedObjects(strippedBuf.data(), static_cast<uint32_t>(strippedBuf.size()));
    ParsedRequest strippedRequest(request.addresses, request.header, strippedObjects);

    executingAuthenticatedAPDU = true;
    this->state = &this->ProcessNewRequest(strippedRequest);
    executingAuthenticatedAPDU = false;
    return true;
}

void OContext::ExecutePendingCriticalAPDU()
{
    if (pendingCriticalAPDU.empty())
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::WARN, "No pending critical APDU to execute");
        return;
    }

    SIMPLE_LOG_BLOCK(this->logger, flags::INFO, "Executing authenticated critical APDU");

    // pendingCriticalAPDU contains the full AL fragment [AppCtrl][FC][objects...]
    // APDUHeaderParser::ParseRequest expects exactly this format
    ser4cpp::rseq_t raw(pendingCriticalAPDU.data(),
                        static_cast<uint32_t>(pendingCriticalAPDU.size()));

    const auto result = APDUHeaderParser::ParseRequest(raw, &this->logger);
    if (!result.success)
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "Failed to parse pending critical APDU");
        pendingCriticalAPDU.clear();
        return;
    }

    pendingCriticalAPDU.clear();
    pendingCriticalUserNum = 0;

    // Set flag BEFORE ProcessRequest to prevent re-challenge inside OnReceiveSolRequest.
    // Keep saKeyExchangeInProgress=true here so OnReceive() does NOT call CheckForTaskStart()
    // between sending the FC=0x81 response and the master's next message. Clearing it here
    // would race with unsolicited null transmission and corrupt the solicited response.
    executingAuthenticatedAPDU = true;

    // Reset request history so the authenticated APDU is never matched as a
    // "repeat" of the challenged request (same SEQ=0 + same objects → same digest).
    // Without this, RequestHistory::FullyEqualsLastRequest() returns true and
    // OnRepeatNonReadRequest() retransmits sol.tx instead of processing the APDU.
    this->history.Reset();

    // Safety net: strip g120v3 prefix if it leaked into pendingCriticalAPDU
    // (happens when Aggressive Mode WRITE arrived while keys were NOT_OK → fell through
    // to challenge; after key exchange the stored APDU still contains g120v3 prefix).
    {
        const uint8_t* objData = static_cast<const uint8_t*>(result.objects);
        const size_t   objLen  = result.objects.length();
        if (objLen >= 3 && objData[0] == 0x78 && objData[1] == 0x03)
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::WARN,
                "ExecutePendingCriticalAPDU: stripping leaked g120v3 prefix");
            const uint8_t q = objData[2];
            size_t skipLen  = 0;
            if (q == 0x5B && objLen >= 6)
            {
                const uint16_t sz = static_cast<uint16_t>(objData[4])
                                  | (static_cast<uint16_t>(objData[5]) << 8);
                skipLen = 6 + static_cast<size_t>(sz);
            }
            else if (q == 0x07 && objLen >= 4)
            {
                skipLen = 4 + sizeof(Group120Var3);  // 10 bytes: hdr(4)+CSQ(4)+USR(2)
            }
            if (skipLen > 0 && skipLen <= objLen)
            {
                ser4cpp::rseq_t stripped(objData + skipLen,
                                         static_cast<uint32_t>(objLen - skipLen));
                ParsedRequest stripped_req(pendingCriticalAddresses, result.header, stripped);
                this->ProcessRequest(stripped_req);
                return;
            }
        }
    }

    // Use original request addresses so response routes to master (not back to outstation).
    ParsedRequest request(pendingCriticalAddresses, result.header, result.objects);
    this->ProcessRequest(request);

    executingAuthenticatedAPDU = false;

    // Clear history after executing authenticated critical APDU.
    // ProcessNewRequest() just recorded the APDU; without this reset the
    // master's next identical request (same SEQ + objects after MDRP restart)
    // is treated as a repeat and silently retransmitted, keeping DEVICE_RESTART
    // set and locking GeoSCADA in an infinite key-exchange loop.
    this->history.Reset();

    // SA mode: auto-clear DEVICE_RESTART so GeoSCADA MDRP can proceed to Integrity Poll
    // instead of treating DEVICE_RESTART in the FC=0x81 response as a full MDRP restart.
    // In non-SA mode, the master clears DEVICE_RESTART via g80v1 WRITE at MDRP end.
    // In SA mode, GeoSCADA receives the authenticated FC=0x81 response and sees DEVICE_RESTART
    // → restarts MDRP from scratch, triggering another key exchange and infinite loop.
    if (saMode != SAMode::NONE)
        this->staticIIN.ClearBit(IINBit::DEVICE_RESTART);

    // saKeyExchangeInProgress is cleared in ProcessNewRequest() when master sends the next
    // solicited request (Integrity Poll). Do not clear it here — clearing it before the
    // FC=0x81 response is transmitted causes CheckForTaskStart() to fire a NULL unsolicited
    // immediately, racing with the solicited response and making Geo SCADA see "Invalid Key Status".
}

// ============================================================
// SAv5 INTEGRATION: Handle AUTH_REQUEST messages
// ============================================================
bool OContext::OnReceiveSAMessage(const ParsedRequest& request)
{
    if (saMode == SAMode::NONE || !saKeyManager || !saChallenger || !saResponder)
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::WARN, "Received AUTH_REQUEST but SA not enabled");
        return false;
    }

    // FIX 1: Track SA sequence separately — never write sol.seq.num here.
    // SA messages always carry SEQ=0; writing sol.seq.num=0 corrupts repeat-request
    // detection and causes DISABLE_UNSOLICITED to be treated as a retransmit.
    this->saSeqNum_ = static_cast<uint8_t>(request.header.control.SEQ);

    SIMPLE_LOG_BLOCK(this->logger, flags::INFO, "Processing AUTH_REQUEST");

    // Implicit conversion: rseq_t → const uint8_t* via operator uint8_t const*()
    const uint8_t* data = static_cast<const uint8_t*>(request.objects);
    const size_t len = request.objects.length();

    if (len < 3)
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "AUTH_REQUEST payload too short");
        return false;
    }

    // Step 1: Detect group and variation from raw object header
    // Group120Parser::Dispatch reads: data[0]=group, data[1]=variation, data[2]=qualifier
    uint8_t groupOut = 0;
    uint8_t variationOut = 0;
    if (!Group120Parser::Dispatch(data, len, groupOut, variationOut))
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::WARN, "Not a recognized Group 120 object");
        return false;
    }

    // Step 2: Calculate payload offset past the DNP3 object header
    //
    // DNP3 object header structure for Group 120:
    //   Byte 0  : Group (0x78 = 120)
    //   Byte 1  : Variation
    //   Byte 2  : Qualifier
    //
    //   Qualifier 0x5B (16-bit Free-Format):
    //     Byte 3       : count of objects (usually 1)
    //     Bytes 4-5    : size of first object (little-endian uint16)
    //     Bytes 6+     : object payload
    //
    //   Qualifier 0x07 (1-byte Count, no range):
    //     Byte 3       : count
    //     Bytes 4+     : object payload

    const uint8_t qualifier = data[2];
    size_t headerLen = 3;
    size_t payloadLen = 0;

    if (qualifier == 0x5B) // 16-bit Free-Format Count (most common for SAv5)
    {
        if (len < 6)
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "Object too short for qualifier 0x5B");
            return false;
        }
        const uint16_t objSize = static_cast<uint16_t>(data[4])
                               | (static_cast<uint16_t>(data[5]) << 8);
        headerLen = 6;
        payloadLen = static_cast<size_t>(objSize);
    }
    else if (qualifier == 0x07) // 1-byte Count, no range
    {
        if (len < 4)
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "Object too short for qualifier 0x07");
            return false;
        }
        headerLen = 4;
        payloadLen = len - headerLen;
    }
    else
    {
        // Unknown qualifier: skip 3-byte header, pass remaining bytes
        payloadLen = len - headerLen;
    }

    if (headerLen + payloadLen > len)
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "Declared payload size exceeds buffer");
        return false;
    }

    const uint8_t* payload = data + headerLen;
    bool handled = false;

    // Step 3: Dispatch to specific static parser based on variation
    switch (variationOut)
    {
    // ---- g120v2 Reply (Aggressive Mode Response) ----
    case 2:
    {
        Group120Var2 var2;
        std::vector<uint8_t> macValue;
        if (Group120Parser::ParseReply(payload, payloadLen, var2, macValue))
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::INFO, "Received g120v2 Reply");

            std::array<uint8_t, 32> controlKey;
            controlKey.fill(0);

            auto keyIt = sessionControlKeys.find(var2.userNumber);
            if (keyIt != sessionControlKeys.end())
            {
                controlKey = keyIt->second;
            }
            else
            {
                FORMAT_LOG_BLOCK(this->logger, flags::ERR,
                                "No cached CDSK for user %u - reply will fail validation",
                                static_cast<unsigned>(var2.userNumber)
                );
            }

            bool valid = saChallenger->ValidateReply(
                var2,
                macValue,
                pendingChallengeAPDU,  // complete AL fragment of g120v1 sent to master
                pendingCriticalAPDU,   // complete AL fragment of WRITE request
                controlKey,
                static_cast<int>(saKeyManager->GetSessionKeyLen())
            );

            if (valid)
            {
                SIMPLE_LOG_BLOCK(this->logger, flags::INFO,
                    "g120v2 Reply validated - APDU execution deferred until after key exchange");
                pendingAuthenticatedReady = true;
                // Wait for master's key status check (g120v4→g120v5) before executing deferred APDU.
                // GeoSCADA pipelines [g120v2][g120v4] — g120v4 handler cancels this timer early.
                // The 200ms fallback fires only if master does not pipeline g120v4.
                awaitingKeyExchangeAfterReply = true;
                keyExchangeWaitTimer_.cancel();
                keyExchangeWaitTimer_ = this->executor->start(
                    std::chrono::milliseconds(200),
                    [this]() {
                        if (awaitingKeyExchangeAfterReply)
                        {
                            SIMPLE_LOG_BLOCK(this->logger, flags::INFO,
                                "Key exchange wait timeout - executing deferred APDU without key exchange");
                            awaitingKeyExchangeAfterReply = false;
                            this->CheckForTaskStart();
                        }
                    }
                );
            }
            else
            {
                SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "g120v2 Reply validation FAILED");
                saKeyManager->InvalidateKeys(var2.userNumber, KeyStatus::AUTH_FAIL);
                pendingCriticalAPDU.clear();
                pendingCriticalUserNum = 0;
                pendingAuthenticatedReady = false;
                awaitingKeyExchangeAfterReply = false;
                keyExchangeWaitTimer_.cancel();
            }
            handled = true;
        }
        else
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "ParseReply failed - malformed g120v2");
        }
        break;
    }

    // ---- g120v3 Aggressive Mode Request ----
    // Logging only: actual APDU execution happens in TryHandleAggressiveMode
    // called from OnReceiveSolRequest when the WRITE+g120v3 arrives as a solicited request.
    case 3:
    {
        Group120Var3 var3;
        if (Group120Parser::ParseAggressiveModeReq(payload, payloadLen, var3))
        {
            FORMAT_LOG_BLOCK(this->logger, flags::INFO,
                "Received g120v3 Aggressive Mode Request: CSQ=%u, User=%u",
                static_cast<unsigned>(var3.csq),
                static_cast<unsigned>(var3.userNumber));
            handled = true;
        }
        else
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::ERR,
                "ParseAggressiveModeReq failed - malformed g120v3");
        }
        break;
    }

    // ---- g120v4 Session Key Status Request ----
    case 4:
    {
        Group120Var4 var4;
        if (Group120Parser::ParseKeyStatusRequest(payload, payloadLen, var4))
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::INFO, "Received g120v4 Key Status Request");

            // If g120v4 arrives while waiting after a validated g120v2 reply, this is
            // GeoSCADA's pipelined post-challenge key status check — not a new key exchange.
            // Session keys are already valid; do not set saKeyExchangeInProgress.
            const bool postChallengeStatusCheck = (pendingAuthenticatedReady && awaitingKeyExchangeAfterReply);
            saKeyExchangeInProgress = !postChallengeStatusCheck;

            // Verify MAC before sending key status (g120v5).
            std::vector<uint8_t> keyStatusBytes;
            auto mdkIt = sessionMonitorKeys.find(var4.userNumber);
            if (mdkIt != sessionMonitorKeys.end() &&
                saKeyManager->GetKeyStatus(var4.userNumber) == KeyStatus::OK)
            {
                const MACAlgorithm statusAlgo = (saMode == SAMode::SAV2)
                    ? MACAlgorithm::HMAC_SHA1_TRUNC_10
                    : MACAlgorithm::HMAC_SHA256_TRUNC_8;
                keyStatusBytes = saKeyManager->OnKeyStatusRequestWithMAC(
                    var4.userNumber,
                    mdkIt->second,
                    statusAlgo
                );
            }
            else
            {
                // Keys are not initialized → g120v5 without MAC
                keyStatusBytes = saKeyManager->OnKeyStatusRequest(var4.userNumber);
            }

            SendKeyStatusResponse(var4.userNumber, keyStatusBytes);

            if (postChallengeStatusCheck)
            {
                SIMPLE_LOG_BLOCK(this->logger, flags::INFO,
                    "g120v4 post-challenge status check: unblocking deferred APDU execution");
                keyExchangeWaitTimer_.cancel();
                awaitingKeyExchangeAfterReply = false;
                // CheckForTaskStart is invoked by OnTxReady after g120v5 TX completes
            }

            handled = true;
        }
        else
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "ParseKeyStatusRequest failed - malformed g120v4");
        }
        break;
    }

    // ---- g120v6 Key Change ----
    case 6:
    {
        Group120Var6 var6;
        std::vector<uint8_t> wrappedKeyData;
        
        if (Group120Parser::ParseKeyChange(payload, payloadLen, var6, wrappedKeyData))
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::INFO, "Received g120v6 Key Change");

            // Build the full Application Layer fragment for MAC computation.
            // Per IEEE 1815-2012 Table A-4, MAC input = the ENTIRE AL fragment
            // of the received Key Change message, including AL Control and Function Code.
            // 'data' points to the object bytes (after the 2-byte AL header).
            // We must prepend the AL header (control byte + function code) manually.
            std::vector<uint8_t> alFragment;
            alFragment.reserve(2 + len);

            // Serialize AppControlField back to 1 byte:
            // bit7=FIR, bit6=FIN, bit5=CON, bit4=UNS, bit3..0=SEQ
            uint8_t alCtrl = 0;
            if (request.header.control.FIR) alCtrl |= 0x80;
            if (request.header.control.FIN) alCtrl |= 0x40;
            if (request.header.control.CON) alCtrl |= 0x20;
            if (request.header.control.UNS) alCtrl |= 0x10;
            alCtrl |= static_cast<uint8_t>(request.header.control.SEQ) & 0x0F;

            alFragment.push_back(alCtrl);
            alFragment.push_back(static_cast<uint8_t>(request.header.function)); // 0x20
            alFragment.insert(alFragment.end(), data, data + len); // 100 object bytes

            uint16_t userNum = 0;
            std::array<uint8_t, 32> controlKey;
            std::array<uint8_t, 32> monitorKey;
            controlKey.fill(0);
            monitorKey.fill(0);

            bool success = saKeyManager->OnKeyChange(
                var6,
                wrappedKeyData,
                alFragment,
                userNum,
                controlKey,
                monitorKey
            );
            if (success)
            {
                saResponder->SetSessionKeys(userNum, controlKey, monitorKey);

                sessionControlKeys[userNum] = controlKey;
                sessionMonitorKeys[userNum] = monitorKey;

                // Confirm with fresh g120v5 Key Status (OK).
                // SAv2: no MAC (MAL=0), SAv5: HMAC-SHA256-trunc8 via Monitor Key.
                const MACAlgorithm confirmAlgo = (saMode == SAMode::SAV2)
                    ? MACAlgorithm::HMAC_SHA1_TRUNC_10
                    : MACAlgorithm::HMAC_SHA256_TRUNC_8;
                auto confirmBytes = saKeyManager->BuildKeyStatusConfirmation(
                    userNum,
                    monitorKey,
                    confirmAlgo
                );
                SendKeyStatusResponse(userNum, confirmBytes);

                // Key exchange is complete: master transitions to Security Idle upon
                // receiving g120v5 OK. Clear the flags so CheckForTaskStart / OnReceive
                // are no longer blocked and the fallback can execute the pending APDU.
                saKeyExchangeInProgress = false;
                awaitingKeyExchangeAfterReply = false;
                keyExchangeWaitTimer_.cancel();

                // Block unsolicited until the next genuine solicited request confirms
                // the master has processed the key change and is in normal operation.
                saUnsolBlocked_ = true;

                FORMAT_LOG_BLOCK(this->logger, flags::INFO,
                                 "Session keys updated for user %u", userNum);
                // pendingAuthenticatedReady (if true) will be picked up by
                // CheckForTaskStart once the g120v5 TX completes (OnTxReady).
            }
            else
            {
                FORMAT_LOG_BLOCK(this->logger, flags::ERR,
                                 "Key Change failed for user %u", var6.userNumber);
            }
            handled = true;
        }
        else
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "ParseKeyChange failed - malformed g120v6");
        }
        break;
    }

    // ---- g120v7 Authentication Error (master reports auth failure) ----
    case 7:
    {
        Group120Var7 var7;
        std::vector<uint8_t> errorText;
        if (Group120Parser::ParseAuthError(payload, payloadLen, var7, errorText))
        {
            if (saResponder)
                saResponder->OnAuthError(var7, errorText);

            std::string text(errorText.begin(), errorText.end());
            FORMAT_LOG_BLOCK(this->logger, flags::WARN,
                "Received g120v7 Auth Error: code=%u, user=%u, text=\"%s\"",
                static_cast<unsigned>(var7.errorCode),
                static_cast<unsigned>(var7.userNumber),
                text.c_str());

            // Auth error means master rejected our Key Status — invalidate keys and
            // reset the key exchange so master can retry.
            if (saKeyManager)
                saKeyManager->InvalidateKeys(var7.userNumber, KeyStatus::AUTH_FAIL);
            saKeyExchangeInProgress = false;

            handled = true;
        }
        else
        {
            SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "ParseAuthError failed - malformed g120v7");
        }
        break;
    }

    default:
        FORMAT_LOG_BLOCK(this->logger, flags::WARN,
                         "Unhandled Group %u Variation %u in AUTH_REQUEST",
                         groupOut, variationOut);
        break;
    }

    return handled;
}

OutstationState& OContext::OnReceiveSolRequest(const ParsedRequest& request)
{
    // Repeat-detection FIRST — before any SA re-challenge check.
    // A deferred copy of an already-authenticated request must retransmit
    // the cached response, not trigger a new challenge.
    if (this->history.HasLastRequest()
        && this->sol.seq.num.Equals(request.header.control.SEQ)
        && this->history.FullyEqualsLastRequest(request.header, request.objects))
    {
        if (request.header.function == FunctionCode::READ)
            return this->state->OnRepeatReadRequest(*this, request);
        return this->state->OnRepeatNonReadRequest(*this, request);
    }

    // ============================================================
    // SAv5 INTEGRATION: Intercept NEW critical functions for auth
    // ============================================================

    // Aggressive Mode must be checked before the !executingAuthenticatedAPDU guard.
    // A prior Aggressive Mode response leaves executingAuthenticatedAPDU=true until reset;
    // the next critical request may also carry g120v3 and must not be bypassed.
    if (saMode != SAMode::NONE && saKeyManager && IsCriticalFunction(request.header.function))
    {
        if (TryHandleAggressiveMode(request))
            return *this->state;
    }

    if (saMode != SAMode::NONE
        && saKeyManager
        && IsCriticalFunction(request.header.function)
        && !executingAuthenticatedAPDU
    ) {
        uint16_t userNum = 1;
        KeyStatus keyStatus = saKeyManager->GetKeyStatus(userNum);

        if (keyStatus != KeyStatus::OK)
        {
            FORMAT_LOG_BLOCK(this->logger, flags::WARN,
                             "Critical function %s requires authentication but keys not valid (status=%d)",
                             FunctionCodeSpec::to_human_string(request.header.function), static_cast<int>(keyStatus));
            std::vector<uint8_t> keyStatusBytes = saKeyManager->OnKeyStatusRequest(userNum);
            SendKeyStatusResponse(userNum, keyStatusBytes);
            return StateIdle::Inst();
        }

        if (InitiateChallengeForCriticalFunction(request))
            return StateIdle::Inst();

        SIMPLE_LOG_BLOCK(this->logger, flags::ERR,
            "SA challenge generation failed - rejecting critical function request");
        return StateIdle::Inst();
    }

    // New request with new SEQ (or SA disabled)
    return this->ProcessNewRequest(request);
}

OutstationState& OContext::ProcessNewRequest(const ParsedRequest& request)
{
    this->sol.seq.num = request.header.control.SEQ;
    this->history.RecordLastProcessedRequest(request.header, request.objects);

    // Restore unsolicited on the first genuine solicited request after key exchange.
    // saUnsolBlocked_ is set exclusively in the g120v6 handler — not touched by the
    // normal CheckForUnsolicited() flow — so this block fires exactly once per key
    // exchange cycle, not on every poll.
    // Skip when executingAuthenticatedAPDU=true — that path replays a deferred request,
    // not a new master request, and clearing the flag there races with the FC=0x81 TX.
    if (saMode != SAMode::NONE && saUnsolBlocked_ && !executingAuthenticatedAPDU)
    {
        saUnsolBlocked_ = false;
        saKeyExchangeInProgress = false;
        this->shouldCheckForUnsolicited = true;
        SIMPLE_LOG_BLOCK(this->logger, flags::INFO,
            "SA Key Exchange confirmed by master solicited request - resuming unsolicited");
    }

    if (request.header.function == FunctionCode::READ)
    {
        return this->state->OnNewReadRequest(*this, request);
    }

    return this->state->OnNewNonReadRequest(*this, request);
}

bool OContext::ProcessObjects(const ParsedRequest& request)
{
    if (request.addresses.IsBroadcast())
    {
        this->state = &this->state->OnBroadcastMessage(*this, request);
        return true;
    }

    if (Functions::IsNoAckFuncCode(request.header.function))
    {
        // this is the only request we process while we are transmitting
        // because it doesn't require a response of any kind
        return this->ProcessRequestNoAck(request);
    }

    // SAv5 INTEGRATION: Handle AUTH_REQUEST before the isTransmitting check.
    // DeferredRequest holds only one slot — if AUTH_REQUEST (g120v4) were deferred
    // alongside a solicited message, the solicited message would overwrite it, losing
    // the key exchange and leaving GeoSCADA stuck in WAIT_KEY_STATUS.
    // SA responses buffered while isTransmitting=true are sent in OnTxReady().
    if (request.header.function == FunctionCode::AUTH_REQUEST)
    {
        if (saMode != SAMode::NONE)
            return this->OnReceiveSAMessage(request);
        // SA disabled - use application callback
        this->application->OnAuthRequest(request.objects, request.objects.length());
        return true;
    }

    if (request.header.function == FunctionCode::AUTH_REQUEST_NO_ACK)
    {
        if (saMode != SAMode::NONE)
            this->OnReceiveSAMessage(request);
        else
            this->application->OnAuthRequestNoAck(request.objects, request.objects.length());
        return true;
    }

    if (this->isTransmitting)
    {
        this->deferred.Set(request);
        return true;
    }

    if (request.header.function == FunctionCode::CONFIRM)
    {
        return this->ProcessConfirm(request);
    }

    return this->ProcessRequest(request);
}

bool OContext::ProcessRequest(const ParsedRequest& request)
{
    if (request.header.control.UNS)
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Ignoring unsol with invalid function code: %s",
                         FunctionCodeSpec::to_human_string(request.header.function));
        return false;
    }

    this->state = &this->OnReceiveSolRequest(request);
    return true;
}

bool OContext::ProcessConfirm(const ParsedRequest& request)
{
    this->state = &this->state->OnConfirm(*this, request);
    return true;
}

OutstationState& OContext::BeginResponseTx(uint16_t destination, APDUResponse& response)
{
    CheckForBroadcastConfirmation(response);

    const auto data = response.ToRSeq();
    this->sol.tx.Record(response.GetControl(), data);
    this->sol.seq.confirmNum = response.GetControl().SEQ;
    this->BeginTx(destination, data);

    if (response.GetControl().CON)
    {
        this->RestartSolConfirmTimer();
        return StateSolicitedConfirmWait::Inst();
    }

    return StateIdle::Inst();
}

void OContext::BeginRetransmitLastResponse(uint16_t destination)
{
    this->BeginTx(destination, this->sol.tx.GetLastResponse());
}

void OContext::BeginRetransmitLastUnsolicitedResponse()
{
    this->BeginTx(this->addresses.destination, this->unsol.tx.GetLastResponse());
}

void OContext::BeginUnsolTx(APDUResponse& response)
{
    CheckForBroadcastConfirmation(response);

    const auto data = response.ToRSeq();
    this->unsol.tx.Record(response.GetControl(), data);
    this->unsol.seq.confirmNum = this->unsol.seq.num;
    this->unsol.seq.num.Increment();
    this->BeginTx(this->addresses.destination, data);
}

void OContext::BeginTx(uint16_t destination, const ser4cpp::rseq_t& message)
{
    logging::ParseAndLogResponseTx(this->logger, message);
    this->isTransmitting = true;
    this->lower->BeginTransmit(Message(Addresses(this->addresses.source, destination), message));
}

void OContext::CheckForTaskStart()
{
    // Execute an authenticated pending APDU BEFORE processing deferred requests.
    // The deferred queue may hold the same critical request that was already authenticated
    // (pipelined by master); processing it first would trigger a new SA challenge instead
    // of executing the authenticated APDU.
    if (pendingAuthenticatedReady && this->CanTransmit() && !saKeyExchangeInProgress && !awaitingKeyExchangeAfterReply)
    {
        pendingAuthenticatedReady = false;
        SIMPLE_LOG_BLOCK(this->logger, flags::INFO,
            "Executing authenticated APDU (deferred after g120v2)");
        ExecutePendingCriticalAPDU();
        return; // OnTxReady() will call CheckForTaskStart() again for remaining checks
    }

    this->CheckForDeferredRequest();

    // FIX 2: Block NULL unsolicited both DURING and AFTER key exchange.
    // - During exchange (saKeyExchangeInProgress=true): any non-SA ASDU aborts
    //   the key change per IEEE 1815-2012 Table 7-13 event 9.
    // - After exchange (saKeyExchangeInProgress=false, shouldCheckForUnsolicited=false):
    //   a NULL unsolicited with IIN=DEVICE_RESTART causes GeoSCADA to restart MDRP,
    //   which triggers another key exchange and creates an infinite loop.
    // shouldCheckForUnsolicited is set back to true in ProcessNewRequest() once the
    // master sends its first genuine solicited request, confirming it is in normal state.
    if (saMode == SAMode::NONE || (!saKeyExchangeInProgress && this->shouldCheckForUnsolicited))
    {
        this->CheckForUnsolicitedNull();
    }

    if (this->shouldCheckForUnsolicited)
    {
        this->CheckForUnsolicited();
    }
}

void OContext::CheckForDeferredRequest()
{
    if (this->CanTransmit() && this->deferred.IsSet())
    {
        auto handler = [this](const ParsedRequest& request) { return this->ProcessDeferredRequest(request); };
        this->deferred.Process(handler);
    }
}

void OContext::CheckForUnsolicitedNull()
{
    if (this->CanTransmit() && this->state->IsIdle() && this->params.allowUnsolicited)
    {
        if (!this->unsol.completedNull)
        {
            // send a NULL unsolcited message
            auto response = this->unsol.tx.Start();
            build::NullUnsolicited(response, this->unsol.seq.num, this->GetResponseIIN());
            this->RestartUnsolConfirmTimer();
            this->state = this->params.noDefferedReadDuringUnsolicitedNullResponse
                              ? &StateNullUnsolicitedConfirmWait::Inst()
                              : &StateUnsolicitedConfirmWait::Inst();
            this->BeginUnsolTx(response);
        }
    }
}

void OContext::CheckForUnsolicited()
{
    if (this->shouldCheckForUnsolicited && this->CanTransmit() && this->state->IsIdle()
        && this->params.allowUnsolicited)
    {
        this->shouldCheckForUnsolicited = false;

        if (this->unsol.completedNull)
        {
            // are there events to be reported?
            if (this->params.unsolClassMask.Intersects(this->eventBuffer.UnwrittenClassField()))
            {
                auto response = this->unsol.tx.Start();
                auto writer = response.GetWriter();

                this->unsolRetries.Reset();
                this->eventBuffer.Unselect();
                this->eventBuffer.SelectAllByClass(this->params.unsolClassMask);
                this->eventBuffer.Load(writer);

                build::NullUnsolicited(response, this->unsol.seq.num, this->GetResponseIIN());
                this->RestartUnsolConfirmTimer();
                this->state = &StateUnsolicitedConfirmWait::Inst();
                this->BeginUnsolTx(response);
            }
        }
    }
}

bool OContext::ProcessDeferredRequest(const ParsedRequest& request)
{
    if (request.header.function == FunctionCode::CONFIRM)
    {
        this->ProcessConfirm(request);
        return true;
    }

    if (request.header.function == FunctionCode::READ)
    {
        if (this->state->IsIdle())
        {
            this->ProcessRequest(request);
            return true;
        }

        return false;
    }
    else
    {
        this->ProcessRequest(request);
        return true;
    }
}

void OContext::RestartSolConfirmTimer()
{
    auto timeout = [&]() {
        this->state = &this->state->OnConfirmTimeout(*this);
        this->CheckForTaskStart();
    };

    this->confirmTimer.cancel();
    this->confirmTimer = this->executor->start(this->params.solConfirmTimeout.value, timeout);
}

void OContext::RestartUnsolConfirmTimer()
{
    auto timeout = [&]() {
        this->state = &this->state->OnConfirmTimeout(*this);
        this->CheckForTaskStart();
    };

    this->confirmTimer.cancel();
    this->confirmTimer = this->executor->start(this->params.unsolConfirmTimeout.value, timeout);
}

OutstationState& OContext::RespondToNonReadRequest(const ParsedRequest& request)
{
    this->history.RecordLastProcessedRequest(request.header, request.objects);

    auto response = this->sol.tx.Start();
    auto writer = response.GetWriter();
    response.SetFunction(FunctionCode::RESPONSE);
    response.SetControl(AppControlField(true, true, false, false, request.header.control.SEQ));
    auto iin = this->HandleNonReadResponse(request.header, request.objects, writer);
    response.SetIIN(iin | this->GetResponseIIN());
    return this->BeginResponseTx(request.addresses.source, response);
}

OutstationState& OContext::RespondToReadRequest(const ParsedRequest& request)
{
    this->history.RecordLastProcessedRequest(request.header, request.objects);

    auto response = this->sol.tx.Start();
    auto writer = response.GetWriter();
    response.SetFunction(FunctionCode::RESPONSE);
    auto result = this->HandleRead(request.objects, writer);
    result.second.SEQ = request.header.control.SEQ;
    response.SetControl(result.second);
    response.SetIIN(result.first | this->GetResponseIIN());

    return this->BeginResponseTx(request.addresses.source, response);
}

OutstationState& OContext::ContinueMultiFragResponse(const Addresses& addresses, const AppSeqNum& seq)
{
    auto response = this->sol.tx.Start();
    auto writer = response.GetWriter();
    response.SetFunction(FunctionCode::RESPONSE);
    auto control = this->rspContext.LoadResponse(writer);
    control.SEQ = seq;
    response.SetControl(control);
    response.SetIIN(this->GetResponseIIN());

    return this->BeginResponseTx(addresses.source, response);
}

bool OContext::CanTransmit() const
{
    return isOnline && !isTransmitting;
}

IINField OContext::GetResponseIIN()
{
    return this->staticIIN | this->GetDynamicIIN() | this->application->GetApplicationIIN().ToIIN();
}

IINField OContext::GetDynamicIIN()
{
    auto classField = this->eventBuffer.UnwrittenClassField();

    IINField ret;
    ret.SetBitToValue(IINBit::CLASS1_EVENTS, classField.HasClass1());
    ret.SetBitToValue(IINBit::CLASS2_EVENTS, classField.HasClass2());
    ret.SetBitToValue(IINBit::CLASS3_EVENTS, classField.HasClass3());
    ret.SetBitToValue(IINBit::EVENT_BUFFER_OVERFLOW, this->eventBuffer.IsOverflown());

    return ret;
}

void OContext::UpdateLastBroadcastMessageReceived(uint16_t destination)
{
    switch (destination)
    {
    case LinkBroadcastAddress::DontConfirm:
        lastBroadcastMessageReceived.set(LinkBroadcastAddress::DontConfirm);
        break;
    case LinkBroadcastAddress::ShallConfirm:
        lastBroadcastMessageReceived.set(LinkBroadcastAddress::ShallConfirm);
        break;
    case LinkBroadcastAddress::OptionalConfirm:
        lastBroadcastMessageReceived.set(LinkBroadcastAddress::OptionalConfirm);
        break;
    default:
        lastBroadcastMessageReceived.clear();
    }
}

void OContext::CheckForBroadcastConfirmation(APDUResponse& response)
{
    if (lastBroadcastMessageReceived.is_set())
    {
        response.SetIIN(response.GetIIN() | IINField(IINBit::BROADCAST));

        if (lastBroadcastMessageReceived.get() != LinkBroadcastAddress::ShallConfirm)
        {
            lastBroadcastMessageReceived.clear();
        }
        else
        {
            // The broadcast address requested a confirmation
            auto control = response.GetControl();
            control.CON = true;
            response.SetControl(control);
        }
    }
}

bool OContext::ProcessMessage(const Message& message)
{
    // is the message addressed to this outstation
    if (message.addresses.destination != this->addresses.source && !message.addresses.IsBroadcast())
    {
        return false;
    }

    // is the message coming from the expected master?
    if (!this->params.respondToAnyMaster && (message.addresses.source != this->addresses.destination))
    {
        return false;
    }

    FORMAT_HEX_BLOCK(this->logger, flags::APP_HEX_RX, message.payload, 18, 18);

    if (message.addresses.IsBroadcast())
    {
        UpdateLastBroadcastMessageReceived(message.addresses.destination);
    }

    const auto result = APDUHeaderParser::ParseRequest(message.payload, &this->logger);
    if (!result.success)
    {
        return false;
    }

    logging::LogHeader(this->logger, flags::APP_HEADER_RX, result.header);

    if (!result.header.control.IsFirAndFin())
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::WARN, "Ignoring fragment. Requests must have FIR/FIN == 1");
        return false;
    }

    if (result.header.control.CON)
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::WARN, "Ignoring fragment. Requests cannot request confirmation");
        return false;
    }

    return this->ProcessObjects(ParsedRequest(message.addresses, result.header, result.objects));
}

void OContext::HandleNewEvents()
{
    this->shouldCheckForUnsolicited = true;
    this->CheckForTaskStart();
}

void OContext::SetRestartIIN()
{
    this->staticIIN.SetBit(IINBit::DEVICE_RESTART);
}

IUpdateHandler& OContext::GetUpdateHandler()
{
    return this->database;
}

//// ----------------------------- function handlers -----------------------------

bool OContext::ProcessBroadcastRequest(const ParsedRequest& request)
{
    switch (request.header.function)
    {
    case (FunctionCode::WRITE):
        this->HandleWrite(request.objects);
        return true;
    case (FunctionCode::DIRECT_OPERATE_NR):
        this->HandleDirectOperate(request.objects, OperateType::DirectOperateNoAck, nullptr);
        return true;
    case (FunctionCode::IMMED_FREEZE_NR):
        this->HandleFreeze(request.objects);
        return true;
    case (FunctionCode::FREEZE_CLEAR_NR):
        this->HandleFreezeAndClear(request.objects);
        return true;
    case (FunctionCode::ASSIGN_CLASS):
    {
        if (this->application->SupportsAssignClass())
        {
            this->HandleAssignClass(request.objects);
            return true;
        }
        else
        {
            return false;
        }
    }
    case (FunctionCode::RECORD_CURRENT_TIME):
    {
        if (request.objects.is_not_empty())
        {
            this->HandleRecordCurrentTime();
            return true;
        }
        else
        {
            return false;
        }
    }
    case (FunctionCode::DISABLE_UNSOLICITED):
    {
        if (this->params.allowUnsolicited)
        {
            this->HandleDisableUnsolicited(request.objects, nullptr);
            return true;
        }
        else
        {
            return false;
        }
    }
    case (FunctionCode::ENABLE_UNSOLICITED):
    {
        if (this->params.allowUnsolicited)
        {
            this->HandleEnableUnsolicited(request.objects, nullptr);
            return true;
        }
        else
        {
            return false;
        }
    }
    default:
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Ignoring broadcast on function code: %s",
                         FunctionCodeSpec::to_string(request.header.function));
        return false;
    }
}

bool OContext::ProcessRequestNoAck(const ParsedRequest& request)
{
    switch (request.header.function)
    {
    case (FunctionCode::DIRECT_OPERATE_NR):
        this->HandleDirectOperate(request.objects, OperateType::DirectOperateNoAck,
                                   nullptr); // no object writer, this is a no ack code
        return true;
    case (FunctionCode::IMMED_FREEZE_NR):
        this->HandleFreeze(request.objects);
        return true;
    case (FunctionCode::FREEZE_CLEAR_NR):
        this->HandleFreezeAndClear(request.objects);
        return true;
    default:
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Ignoring NR function code: %s",
                         FunctionCodeSpec::to_human_string(request.header.function));
        return false;
    }
}

IINField OContext::HandleNonReadResponse(const APDUHeader& header, const ser4cpp::rseq_t& objects, HeaderWriter& writer)
{
    switch (header.function)
    {
    case (FunctionCode::WRITE):
        return this->HandleWrite(objects);
    case (FunctionCode::SELECT):
        return this->HandleSelect(objects, writer);
    case (FunctionCode::OPERATE):
        return this->HandleOperate(objects, writer);
    case (FunctionCode::DIRECT_OPERATE):
        return this->HandleDirectOperate(objects, OperateType::DirectOperate, &writer);
    case (FunctionCode::COLD_RESTART):
        return this->HandleRestart(objects, false, &writer);
    case (FunctionCode::WARM_RESTART):
        return this->HandleRestart(objects, true, &writer);
    case (FunctionCode::ASSIGN_CLASS):
        return this->HandleAssignClass(objects);
    case (FunctionCode::DELAY_MEASURE):
        return this->HandleDelayMeasure(objects, writer);
    case (FunctionCode::RECORD_CURRENT_TIME):
        return objects.is_empty() ? this->HandleRecordCurrentTime() : IINField(IINBit::PARAM_ERROR);
    case (FunctionCode::DISABLE_UNSOLICITED):
        return this->params.allowUnsolicited ? this->HandleDisableUnsolicited(objects, &writer)
                                              : IINField(IINBit::FUNC_NOT_SUPPORTED);
    case (FunctionCode::ENABLE_UNSOLICITED):
        return this->params.allowUnsolicited ? this->HandleEnableUnsolicited(objects, &writer)
                                              : IINField(IINBit::FUNC_NOT_SUPPORTED);
    case (FunctionCode::IMMED_FREEZE):
        return this->HandleFreeze(objects);
    case (FunctionCode::FREEZE_CLEAR):
        return this->HandleFreezeAndClear(objects);
    // ============================================================
    // SAv5 INTEGRATION: Handle AUTH_REQUEST function code
    // ============================================================
    case (FunctionCode::AUTH_REQUEST):
    {
        // When saMode != NONE, AUTHREQUEST is intercepted in ProcessObjects
        // and never reaches here. This is a safety fallback for saMode == NONE only.
        if (saMode == SAMode::NONE)
        {
            this->application->OnAuthRequest(objects, objects.length());
        }
        return IINField::Empty();
    }
    case (FunctionCode::AUTH_REQUEST_NO_ACK):
        // Same as above - only reached when saMode == NONE
        if (saMode == SAMode::NONE)
        {
            this->application->OnAuthRequestNoAck(objects, objects.length());
        }
        return IINField::Empty();
    default:
        return IINField(IINBit::FUNC_NOT_SUPPORTED);
    }
}

ser4cpp::Pair<IINField, AppControlField> OContext::HandleRead(const ser4cpp::rseq_t& objects, HeaderWriter& writer)
{
    this->rspContext.Reset();
    this->eventBuffer.Unselect(); // always un-select any previously selected points when we start a new read request
    this->database.Unselect();

    ReadHandler handler(this->database, this->eventBuffer);
    auto result = APDUParser::Parse(objects, handler, &this->logger,
                                     ParserSettings::NoContents()); // don't expect range/count context on a READ
    if (result == ParseResult::OK)
    {
        auto control = this->rspContext.LoadResponse(writer);
        return ser4cpp::Pair<IINField, AppControlField>(handler.Errors(), control);
    }

    this->rspContext.Reset();
    return ser4cpp::Pair<IINField, AppControlField>(IINFromParseResult(result),
                                                     AppControlField(true, true, false, false));
}

IINField OContext::HandleWrite(const ser4cpp::rseq_t& objects)
{
    WriteHandler handler(*this->application, this->time, this->sol.seq.num, Timestamp(this->executor->get_time()),
                         &this->staticIIN);
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    return (result == ParseResult::OK) ? handler.Errors() : IINFromParseResult(result);
}

IINField OContext::HandleDirectOperate(const ser4cpp::rseq_t& objects, OperateType opType, HeaderWriter* pWriter)
{
    // since we're echoing, make sure there's enough size before beginning
    if (pWriter && (objects.length() > pWriter->Remaining()))
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Igonring command request due to oversized payload size of %zu",
                         objects.length());
        return IINField(IINBit::PARAM_ERROR);
    }

    CommandActionAdapter adapter(*this->commandHandler, false, this->database, opType);
    CommandResponseHandler handler(this->params.maxControlsPerRequest, &adapter, pWriter);
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    this->shouldCheckForUnsolicited = true;
    return (result == ParseResult::OK) ? handler.Errors() : IINFromParseResult(result);
}

IINField OContext::HandleSelect(const ser4cpp::rseq_t& objects, HeaderWriter& writer)
{
    // since we're echoing, make sure there's enough size before beginning
    if (objects.length() > writer.Remaining())
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Igonring command request due to oversized payload size of %zu",
                         objects.length());
        return IINField(IINBit::PARAM_ERROR);
    }

    // the 'OperateType' is just ignored since it's a select
    CommandActionAdapter adapter(*this->commandHandler, true, this->database, OperateType::DirectOperate);
    CommandResponseHandler handler(this->params.maxControlsPerRequest, &adapter, &writer);
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    if (result == ParseResult::OK)
    {
        if (handler.AllCommandsSuccessful())
        {
            this->control.Select(this->sol.seq.num, Timestamp(this->executor->get_time()), objects);
        }

        return handler.Errors();
    }

    return IINFromParseResult(result);
}

IINField OContext::HandleOperate(const ser4cpp::rseq_t& objects, HeaderWriter& writer)
{
    // since we're echoing, make sure there's enough size before beginning
    if (objects.length() > writer.Remaining())
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Igonring command request due to oversized payload size of %zu",
                         objects.length());
        return IINField(IINBit::PARAM_ERROR);
    }

    auto now = Timestamp(this->executor->get_time());
    auto result = this->control.ValidateSelection(this->sol.seq.num, now, this->params.selectTimeout, objects);

    if (result == CommandStatus::SUCCESS)
    {
        CommandActionAdapter adapter(*this->commandHandler, false, this->database, OperateType::SelectBeforeOperate);
        CommandResponseHandler handler(this->params.maxControlsPerRequest, &adapter, &writer);
        auto result = APDUParser::Parse(objects, handler, &this->logger);
        this->shouldCheckForUnsolicited = true;
        return (result == ParseResult::OK) ? handler.Errors() : IINFromParseResult(result);
    }
    else
    {
        this->control.Unselect();
    }

    return this->HandleCommandWithConstant(objects, writer, result);
}

IINField OContext::HandleDelayMeasure(const ser4cpp::rseq_t& objects, HeaderWriter& writer)
{
    if (objects.is_empty())
    {
        Group52Var2 value;
        value.time = 0; // respond with 0 time delay
        writer.WriteSingleValue<ser4cpp::UInt8, Group52Var2>(QualifierCode::UINT8_CNT, value);
        return IINField::Empty();
    }

    // there shouldn't be any trailing headers in delay measure request, no need to even parse
    return IINField(IINBit::PARAM_ERROR);
}

IINField OContext::HandleRecordCurrentTime()
{
    this->time.RecordCurrentTime(this->sol.seq.num, Timestamp(this->executor->get_time()));
    return IINField::Empty();
}

IINField OContext::HandleRestart(const ser4cpp::rseq_t& objects, bool isWarmRestart, HeaderWriter* pWriter)
{
    if (objects.is_not_empty())
        return IINField(IINBit::PARAM_ERROR);

    auto mode = isWarmRestart ? this->application->WarmRestartSupport() : this->application->ColdRestartSupport();

    switch (mode)
    {
    case (RestartMode::UNSUPPORTED):
        return IINField(IINBit::FUNC_NOT_SUPPORTED);
    case (RestartMode::SUPPORTED_DELAY_COARSE):
    {
        auto delay = isWarmRestart ? this->application->WarmRestart() : this->application->ColdRestart();
        if (pWriter)
        {
            Group52Var1 coarse;
            coarse.time = delay;
            pWriter->WriteSingleValue<ser4cpp::UInt8>(QualifierCode::UINT8_CNT, coarse);
        }
        return IINField::Empty();
    }
    default:
    {
        auto delay = isWarmRestart ? this->application->WarmRestart() : this->application->ColdRestart();
        if (pWriter)
        {
            Group52Var2 fine;
            fine.time = delay;
            pWriter->WriteSingleValue<ser4cpp::UInt8>(QualifierCode::UINT8_CNT, fine);
        }
        return IINField::Empty();
    }
    }
}

IINField OContext::HandleAssignClass(const ser4cpp::rseq_t& objects)
{
    if (this->application->SupportsAssignClass())
    {
        AssignClassHandler handler(*this->application, this->database);
        auto result = APDUParser::Parse(objects, handler, &this->logger, ParserSettings::NoContents());
        return (result == ParseResult::OK) ? handler.Errors() : IINFromParseResult(result);
    }

    return IINField(IINBit::FUNC_NOT_SUPPORTED);
}

IINField OContext::HandleDisableUnsolicited(const ser4cpp::rseq_t& objects, HeaderWriter* /*writer*/)
{
    ClassBasedRequestHandler handler;
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    if (result == ParseResult::OK)
    {
        this->params.unsolClassMask.Clear(handler.GetClassField());
        return handler.Errors();
    }

    return IINFromParseResult(result);
}

IINField OContext::HandleEnableUnsolicited(const ser4cpp::rseq_t& objects, HeaderWriter* /*writer*/)
{
    ClassBasedRequestHandler handler;
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    if (result == ParseResult::OK)
    {
        this->params.unsolClassMask.Set(handler.GetClassField());
        this->shouldCheckForUnsolicited = true;
        return handler.Errors();
    }

    return IINFromParseResult(result);
}

IINField OContext::HandleCommandWithConstant(const ser4cpp::rseq_t& objects, HeaderWriter& writer, CommandStatus status)
{
    ConstantCommandAction constant(status);
    CommandResponseHandler handler(this->params.maxControlsPerRequest, &constant, &writer);
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    return IINFromParseResult(result);
}

IINField OContext::HandleFreeze(const ser4cpp::rseq_t& objects)
{
    FreezeRequestHandler handler(false, database);
    auto result = APDUParser::Parse(objects, handler, &this->logger, ParserSettings::NoContents());
    return IINFromParseResult(result);
}

IINField OContext::HandleFreezeAndClear(const ser4cpp::rseq_t& objects)
{
    FreezeRequestHandler handler(true, database);
    auto result = APDUParser::Parse(objects, handler, &this->logger, ParserSettings::NoContents());
    return IINFromParseResult(result);
}

} // namespace opendnp3
