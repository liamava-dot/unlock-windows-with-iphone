// Created by Rui MA on 13 Oct 2026

#pragma once

#include "SystemBleSession.h"
#include <functional>
#include <string>
#include <utility>

namespace unlock_windows::system_ble {
struct RssiEvidence final {
    Failure failure = Failure::none;
    std::uint64_t started = 0, sampledAt = 0;
    int rssi = -127;
    ConnectionTarget target;
};

namespace detail {
enum class RssiSampleResult {
    inactive, failed, missingTarget, addressMismatch, addressTypeMismatch,
    beforeRequest, beforeTarget, stale, outOfOrder, invalidSignal, accepted
};

// Request-local evidence. The advertisement watcher may outlive a request,
// but every request starts with an empty proof and a new timestamp boundary.
class RssiSamples final {
public:
    RssiSamples(ConnectionTarget target, std::uint64_t started)
        : proof_{Failure::none, started, 0, -127, std::move(target)}, targetSince_(started) {}

    void beginRequest(ConnectionTarget target, std::uint64_t started) {
        proof_ = {Failure::none, started, 0, -127, std::move(target)};
        targetSince_ = started;
        active_ = true;
    }

    void endRequest() noexcept {
        active_ = false;
        proof_.failure = Failure::cancelled;
        proof_.sampledAt = 0;
        proof_.rssi = -127;
    }

    // GATT revision changes do not change the BLE radio identity. Keep a
    // request-fresh sample when endpoint/address/type are unchanged; discard
    // it only when the physical target actually changes.
    bool updateTarget(ConnectionTarget target, std::uint64_t now) {
        if (proof_.target == target) return false;
        const bool sameRadio = proof_.target.endpointId == target.endpointId &&
            proof_.target.address == target.address && proof_.target.addressType == target.addressType;
        if (!sameRadio) {
            proof_.sampledAt = 0;
            proof_.rssi = -127;
            targetSince_ = now;
        }
        proof_.target = std::move(target);
        return true;
    }

    RssiSampleResult record(std::uint64_t address, winrt::Windows::Devices::Bluetooth::BluetoothAddressType type,
        std::uint64_t sampledAt, int rssi, std::uint64_t now) noexcept {
        if (!active_) return RssiSampleResult::inactive;
        if (proof_.failure != Failure::none) return RssiSampleResult::failed;
        if (!proof_.target.address) return RssiSampleResult::missingTarget;
        if (address != proof_.target.address) return RssiSampleResult::addressMismatch;
        if (type != proof_.target.addressType) return RssiSampleResult::addressTypeMismatch;
        if (sampledAt < proof_.started) return RssiSampleResult::beforeRequest;
        if (sampledAt < targetSince_) return RssiSampleResult::beforeTarget;
        if (!freshEvidence(sampledAt, proof_.started, now)) return RssiSampleResult::stale;
        if (sampledAt < proof_.sampledAt) return RssiSampleResult::outOfOrder;
        if (rssi < -127 || rssi >= 0) return RssiSampleResult::invalidSignal;
        proof_.sampledAt = sampledAt;
        proof_.rssi = rssi;
        return RssiSampleResult::accepted;
    }

    void fail() noexcept { if (active_) proof_.failure = Failure::rssiUnavailable; }
    void stop() noexcept {
        active_ = false;
        proof_.failure = Failure::cancelled;
        proof_.sampledAt = 0;
        proof_.rssi = -127;
    }
    RssiEvidence evidence(const ConnectionTarget& current) const {
        auto result = proof_;
        if (result.failure == Failure::none && result.target != current) {
            result.sampledAt = 0;
            result.rssi = -127;
        }
        return result;
    }
private:
    RssiEvidence proof_;
    std::uint64_t targetSince_;
    bool active_ = true;
};
}

class RssiSampler final {
public:
    explicit RssiSampler(std::function<void(const std::string&)> report = {}) : reporter_(std::move(report)) {}
    ~RssiSampler();
    RssiSampler(const RssiSampler&) = delete;
    RssiSampler& operator=(const RssiSampler&) = delete;
    // Start passive scanning while a locked session is eligible. No request
    // evidence is collected until beginRequest establishes its time boundary.
    void startBackground(ConnectionTarget target);
    void beginRequest(ConnectionTarget target, std::uint64_t started,
        std::function<void(const std::string&)> report = {});
    // Compatibility entry point for one-shot diagnostics and callers.
    void start(ConnectionTarget target, std::uint64_t started) { beginRequest(std::move(target), started); }
    void updateTarget(ConnectionTarget target);
    RssiEvidence evidence(const ConnectionTarget& current) const;
    std::string diagnostics() const;
    bool healthy() const;
    void endRequest();
    void stop();
private:
    struct State;
    std::shared_ptr<State> state_;
    std::function<void(const std::string&)> reporter_;
};
}
