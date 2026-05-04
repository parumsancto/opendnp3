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
#ifndef OPENDNP3_OUTSTATIONCONTEXT_H
#define OPENDNP3_OUTSTATIONCONTEXT_H

#include "LayerInterfaces.h"
#include "link/LinkLayerConstants.h"
#include "outstation/ControlState.h"
#include "outstation/Database.h"
#include "outstation/DeferredRequest.h"
#include "outstation/OutstationChannelStates.h"
#include "outstation/OutstationSeqNum.h"
#include "outstation/OutstationStates.h"
#include "outstation/ParsedRequest.h"
#include "outstation/RequestHistory.h"
#include "outstation/ResponseContext.h"
#include "outstation/TimeSyncState.h"
#include "outstation/event/EventBuffer.h"

#include "opendnp3/link/Addresses.h"
#include "opendnp3/logging/Logger.h"
#include "opendnp3/outstation/ICommandHandler.h"
#include "opendnp3/outstation/IOutstationApplication.h"
#include "opendnp3/outstation/OutstationConfig.h"

#include <ser4cpp/container/Pair.h>
#include <ser4cpp/container/Settable.h>
#include <exe4cpp/IExecutor.h>

// ============================================================
// SAv5 INTEGRATION: Add Secure Authentication components
// ============================================================
#include "opendnp3/app/secauth/SAResponder.h"
#include "opendnp3/app/secauth/SAChallenger.h"
#include "opendnp3/app/secauth/SAKeyManager.h"
#include "opendnp3/app/secauth/SAMode.h"

#include <functional>
#include <memory>
#include <map>

#include <ser4cpp/container/Buffer.h>

namespace opendnp3
{

///
/// Represent all of the mutable state in an outstation
///
class OContext : public IUpperLayer
{
    friend class StateIdle;
    friend class StateSolicitedConfirmWait;
    friend class StateUnsolicitedConfirmWait;
    friend class StateNullUnsolicitedConfirmWait;

public:
    OContext(const Addresses& addresses,
             const OutstationConfig& config,
             const DatabaseConfig& db_config,
             const Logger& logger,
             const std::shared_ptr<exe4cpp::IExecutor>& executor,
             std::shared_ptr<ILowerLayer> lower,
             std::shared_ptr<ICommandHandler> commandHandler,
             std::shared_ptr<IOutstationApplication> application);

    /// ----- Implement IUpperLayer ------

    virtual bool OnLowerLayerUp() override;

    virtual bool OnLowerLayerDown() override;

    virtual bool OnTxReady() override final;

    virtual bool OnReceive(const Message& message) override final;

    /// --- Other public members ----

    void HandleNewEvents();

    IUpdateHandler& GetUpdateHandler();

    void SetRestartIIN();

private:
    /// ---- Helper functions that operate on the current state, and may return a new state ----

    OutstationState& ContinueMultiFragResponse(const Addresses& addresses, const AppSeqNum& seq);

    OutstationState& RespondToReadRequest(const ParsedRequest& request);

    OutstationState& ProcessNewRequest(const ParsedRequest& request);

    OutstationState& OnReceiveSolRequest(const ParsedRequest& request);

    OutstationState& RespondToNonReadRequest(const ParsedRequest& request);

    // ---- Processing functions --------

    bool ProcessMessage(const Message& message);

    bool ProcessObjects(const ParsedRequest& request);

    bool ProcessRequest(const ParsedRequest& request);

    bool ProcessBroadcastRequest(const ParsedRequest& request);

    bool ProcessRequestNoAck(const ParsedRequest& request);

    bool ProcessConfirm(const ParsedRequest& request);

    // ============================================================
    // SAv5 INTEGRATION: Secure Authentication message handling
    // ============================================================

    /**
     * @brief Handle AUTH_REQUEST (FC 0x20) messages
     * @details Processes g120vX objects:
     *   - v4 Key Status Request → saKeyManager
     *   - v6 Key Change → saKeyManager
     *   - v2 Aggressive Mode Response → saChallenger
     * 
     * IEEE 1815-2012 Section 7.5.5
     * 
     * @param request Parsed AUTH_REQUEST with g120vX objects
     * @return true if handled successfully
     */
    bool OnReceiveSAMessage(const ParsedRequest& request);

    /**
     * @brief Check if function code requires authentication
     * @details Critical functions per IEEE 1815-2012 Table 7-1:
     *   - WRITE, SELECT, OPERATE, DIRECT_OPERATE
     *   - COLD_RESTART, WARM_RESTART
     *   - ENABLE_UNSOLICITED, DISABLE_UNSOLICITED
     * 
     * @param fc Function code to check
     * @return true if critical (requires auth), false if non-critical
     */
    bool IsCriticalFunction(FunctionCode fc) const;

    /**
     * @brief Initiate challenge-response for critical function
     * @details Per IEEE 1815-2012 Figure 7-2:
     *   1. Queue incoming critical APDU
     *   2. Generate challenge via SAChallenger
     *   3. Send g120v1 Challenge to master
     *   4. Wait for g120v2 Aggressive Mode Response
     * 
     * @param request Critical function request to protect
     * @return true if challenge sent successfully
     */
    bool InitiateChallengeForCriticalFunction(const ParsedRequest& request);

    /**
     * @brief Send g120v5 Key Status response
     * @details Called in response to g120v4 Key Status Request
     * 
     * @param userNum User number
     * @param keyStatusBytes g120v5 Key Status payload
     */
    void SendKeyStatusResponse(uint16_t userNum, const std::vector<uint8_t>& keyStatusBytes);

    /**
     * @brief Send g120v1 Challenge
     * @details Challenge-response authentication flow
     * 
     * @param challengeBytes g120v1 Challenge payload
     */
    void SendChallengeMessage(const std::vector<uint8_t>& challengeBytes);

    /**
     * @brief Execute pending critical APDU after successful authentication
     * @details Called when:
     *   - g120v2 Aggressive Mode Response validated successfully
     *   - Session keys updated via g120v6 Key Change
     */
    void ExecutePendingCriticalAPDU();

    // ---- common helper methods ----

    OutstationState& BeginResponseTx(uint16_t destination, APDUResponse& response);

    void BeginRetransmitLastResponse(uint16_t destination);

    void BeginRetransmitLastUnsolicitedResponse();

    void BeginUnsolTx(APDUResponse& response);

    void BeginTx(uint16_t destination, const ser4cpp::rseq_t& message);

    void CheckForTaskStart();

    void CheckForDeferredRequest();

    void CheckForUnsolicitedNull();

    void CheckForUnsolicited();

    bool ProcessDeferredRequest(const ParsedRequest& request);

    void RestartSolConfirmTimer();

    void RestartUnsolConfirmTimer();

    bool CanTransmit() const;

    IINField GetResponseIIN();

    IINField GetDynamicIIN();

    void UpdateLastBroadcastMessageReceived(uint16_t destination);

    void CheckForBroadcastConfirmation(APDUResponse& response);

    /// --- methods for handling app-layer functions ---

    /// Handles non-read function codes that require a response. builds the response using the supplied writer.
    /// @return An IIN field indicating the validity of the request, and to be returned in the response.
    IINField HandleNonReadResponse(const APDUHeader& header, const ser4cpp::rseq_t& objects, HeaderWriter& writer);

    /// Handles read function codes. May trigger an unsolicited response
    /// @return an IIN field and a partial AppControlField (missing sequence info)
    ser4cpp::Pair<IINField, AppControlField> HandleRead(const ser4cpp::rseq_t& objects, HeaderWriter& writer);

    // ------ Function Handlers ------

    IINField HandleWrite(const ser4cpp::rseq_t& objects);
    IINField HandleSelect(const ser4cpp::rseq_t& objects, HeaderWriter& writer);
    IINField HandleOperate(const ser4cpp::rseq_t& objects, HeaderWriter& writer);
    IINField HandleDirectOperate(const ser4cpp::rseq_t& objects, OperateType opType, HeaderWriter* pWriter);
    IINField HandleDelayMeasure(const ser4cpp::rseq_t& objects, HeaderWriter& writer);
    IINField HandleRecordCurrentTime();
    IINField HandleRestart(const ser4cpp::rseq_t& objects, bool isWarmRestart, HeaderWriter* pWriter);
    IINField HandleAssignClass(const ser4cpp::rseq_t& objects);
    IINField HandleDisableUnsolicited(const ser4cpp::rseq_t& objects, HeaderWriter* writer);
    IINField HandleEnableUnsolicited(const ser4cpp::rseq_t& objects, HeaderWriter* writer);
    IINField HandleCommandWithConstant(const ser4cpp::rseq_t& objects, HeaderWriter& writer, CommandStatus status);
    IINField HandleFreeze(const ser4cpp::rseq_t& objects);
    IINField HandleFreezeAndClear(const ser4cpp::rseq_t& objects);

    // ------ resources --------
    const Addresses addresses;
    Logger logger;
    const std::shared_ptr<exe4cpp::IExecutor> executor;
    const std::shared_ptr<ILowerLayer> lower;
    const std::shared_ptr<ICommandHandler> commandHandler;
    const std::shared_ptr<IOutstationApplication> application;

    // ------ Database, event buffer, and response tracking
    EventBuffer eventBuffer;
    Database database;
    ResponseContext rspContext;

    // ------ Static configuration -------
    OutstationParams params;

    // ------ Shared dynamic state --------
    bool isOnline;
    bool isTransmitting;
    IINField staticIIN;
    exe4cpp::Timer confirmTimer;
    RequestHistory history;
    DeferredRequest deferred;

    // ------ Dynamic state related to controls ------
    ControlState control;

    // ------ Dynamic state related to time synchronization ------
    TimeSyncState time;

    // ------ Dynamic state related to solicited and unsolicited modes ------
    OutstationSolState sol;
    OutstationUnsolState unsol;
    NumRetries unsolRetries;
    bool shouldCheckForUnsolicited;
    OutstationState* state = &StateIdle::Inst();

    // ------ Dynamic state related to broadcast messages ------
    //ser4cpp::Settable<uint16_t> lastBroadcastMessageReceived;
    ser4cpp::Settable<LinkBroadcastAddress> lastBroadcastMessageReceived;

    // ============================================================
    // SAv5 INTEGRATION: Secure Authentication state
    // ============================================================

    /// @brief SAv5 components (initialized if saMode != SAMode::NONE)
    std::unique_ptr<SAResponder> saResponder;
    std::unique_ptr<SAChallenger> saChallenger;
    std::unique_ptr<SAKeyManager> saKeyManager;
    std::map<uint16_t, std::array<uint8_t, 32>> sessionControlKeys;  // CDK
    std::map<uint16_t, std::array<uint8_t, 32>> sessionMonitorKeys;  // MDK
    // SAv5: raw transmit buffer for AUTH_RESPONSE (bypasses HeaderWriter).
    // Must outlive BeginTx() until OnTxReady() fires (async TX).
    static constexpr size_t SA_TX_BUFFER_SIZE = 2048;
    std::array<uint8_t, SA_TX_BUFFER_SIZE> saTxBuffer_;

    /// @brief Secure Authentication mode
    SAMode saMode;

    /// @brief Pending critical APDU awaiting authentication
    /// @details Stores serialized APDU bytes to execute after successful auth
    std::vector<uint8_t> pendingCriticalAPDU;
    /// @brief Original source/destination addresses of the intercepted critical request.
    /// @details Used in ExecutePendingCriticalAPDU so the WRITE response is routed back
    ///          to the master (src=master, dst=outstation), not to the outstation itself.
    Addresses pendingCriticalAddresses;
    /// @brief Full AL fragment of g120v1 challenge sent to master (for MAC validation)
    /// @details IEEE 1815-2012 Table A-3: MAC input includes the complete challenge message
    std::vector<uint8_t> pendingChallengeAPDU;

    /// @brief User number of pending critical request
    uint16_t pendingCriticalUserNum;

    bool saKeyExchangeInProgress = false; // true during SA Key Exchange, blocks unsolicited
    bool executingAuthenticatedAPDU = false; 
};

} // namespace opendnp3

#endif
