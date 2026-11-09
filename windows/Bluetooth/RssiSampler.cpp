// Created by Rui MA on 13 Oct 2026

#include <Windows.h>
#undef GetCurrentTime
#include "RssiSampler.h"
#include <winrt/Windows.Devices.Bluetooth.Advertisement.h>
#include <winrt/Windows.Foundation.h>
#include <chrono>
#include <mutex>

namespace unlock_windows::system_ble {
using namespace winrt;
using namespace Windows::Devices::Bluetooth::Advertisement;

struct RssiSampler::State final {
    mutable std::mutex mutex;
    detail::RssiSamples samples;
    BluetoothLEAdvertisementWatcher watcher{nullptr};
    BluetoothLEAdvertisementWatcher::Received_revoker received;
    BluetoothLEAdvertisementWatcher::Stopped_revoker stopped;
    std::function<void(const std::string&)> reporter;
    std::uint64_t watcherStartedAt = 0, requestStartedAt = 0, lastRequestStartedAt = 0;
    std::uint64_t firstWatcherCallbackAt = 0, firstWatcherTargetMatchAt = 0, watcherCallbacks = 0, watcherTargetMatches = 0;
    std::uint64_t firstCallbackAt = 0, firstTargetMatchAt = 0, firstAcceptedAt = 0;
    std::uint64_t callbacks = 0, accepted = 0, addressMismatch = 0, addressTypeMismatch = 0;
    std::uint64_t beforeRequest = 0, beforeTarget = 0, stale = 0, outOfOrder = 0;
    std::uint64_t invalidSignal = 0, invalidTimestamp = 0, targetUpdates = 0, physicalTargetResets = 0;
    bool failed = false;
    State(ConnectionTarget target, std::function<void(const std::string&)> report)
        : samples(std::move(target), 0), reporter(std::move(report)) { samples.endRequest(); }
};

void RssiSampler::startBackground(ConnectionTarget target) {
    if (state_) throw VerificationError(Failure::internalError, "RSSI sampler already started");
    state_ = std::make_shared<State>(std::move(target), reporter_);
    const std::weak_ptr<State> weak = state_;
    const auto startAt = GetTickCount64();
    try {
        {
            std::lock_guard lock(state_->mutex);
            state_->watcherStartedAt = startAt;
        }
        state_->watcher = BluetoothLEAdvertisementWatcher();
        state_->watcher.ScanningMode(mode_ == RssiScanMode::active
            ? BluetoothLEScanningMode::Active : BluetoothLEScanningMode::Passive);
        state_->received = state_->watcher.Received(auto_revoke, [weak](const auto&, const BluetoothLEAdvertisementReceivedEventArgs& args) {
            if (const auto self = weak.lock()) {
                try {
                    const auto now = GetTickCount64();
                    const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(winrt::clock::now() - args.Timestamp()).count();
                    const auto address = args.BluetoothAddress();
                    const auto type = args.BluetoothAddressType();
                    const auto rssi = args.RawSignalStrengthInDBm();
                    std::lock_guard lock(self->mutex);
                    ++self->watcherCallbacks;
                    if (!self->firstWatcherCallbackAt) self->firstWatcherCallbackAt = now;
                    const auto activeTarget = self->samples.evidence({}).target;
                    const bool radioMatch = activeTarget.address == address && activeTarget.addressType == type;
                    if (radioMatch) {
                        ++self->watcherTargetMatches;
                        if (!self->firstWatcherTargetMatchAt) self->firstWatcherTargetMatchAt = now;
                    }
                    if (!self->requestStartedAt || now < self->requestStartedAt) return;
                    ++self->callbacks;
                    if (!self->firstCallbackAt) self->firstCallbackAt = now;
                    if (age < 0 || static_cast<std::uint64_t>(age) > now) {
                        ++self->invalidTimestamp;
                        return;
                    }
                    const auto sampledAt = now - static_cast<std::uint64_t>(age);
                    const auto result = self->samples.record(address, type, sampledAt, rssi, now);
                    if (result != detail::RssiSampleResult::addressMismatch &&
                        result != detail::RssiSampleResult::addressTypeMismatch &&
                        result != detail::RssiSampleResult::missingTarget &&
                        result != detail::RssiSampleResult::inactive &&
                        result != detail::RssiSampleResult::failed && !self->firstTargetMatchAt)
                        self->firstTargetMatchAt = now;
                    switch (result) {
                    case detail::RssiSampleResult::addressMismatch: ++self->addressMismatch; break;
                    case detail::RssiSampleResult::addressTypeMismatch: ++self->addressTypeMismatch; break;
                    case detail::RssiSampleResult::beforeRequest: ++self->beforeRequest; break;
                    case detail::RssiSampleResult::beforeTarget: ++self->beforeTarget; break;
                    case detail::RssiSampleResult::stale: ++self->stale; break;
                    case detail::RssiSampleResult::outOfOrder: ++self->outOfOrder; break;
                    case detail::RssiSampleResult::invalidSignal: ++self->invalidSignal; break;
                    case detail::RssiSampleResult::accepted:
                        ++self->accepted;
                        if (!self->firstAcceptedAt) self->firstAcceptedAt = now;
                        break;
                    default: break;
                    }
                } catch (...) {
                    std::lock_guard lock(self->mutex);
                    self->samples.fail();
                    self->failed = true;
                }
            }
        });
        state_->stopped = state_->watcher.Stopped(auto_revoke, [weak](const auto&, const auto&) {
            if (const auto self = weak.lock()) {
                std::lock_guard lock(self->mutex);
                self->samples.fail();
                self->failed = true;
            }
        });
        state_->watcher.Start();
        const auto readyAt = GetTickCount64();
        if (reporter_) reporter_(std::string("RSSI ") + (mode_ == RssiScanMode::active ? "active" : "passive") +
            " watcher started; startElapsedMs=" + std::to_string(readyAt - startAt));
    } catch (...) {
        std::lock_guard lock(state_->mutex);
        state_->samples.fail();
        state_->failed = true;
        throw VerificationError(Failure::rssiUnavailable, "RSSI advertisement watcher start failed");
    }
}

void RssiSampler::beginRequest(ConnectionTarget target, std::uint64_t started,
    std::function<void(const std::string&)> report) {
    if (!state_) {
        if (report) reporter_ = std::move(report);
        startBackground(target);
    }
    std::string message;
    std::function<void(const std::string&)> notify;
    {
        std::lock_guard lock(state_->mutex);
        if (state_->failed) throw VerificationError(Failure::rssiUnavailable, "RSSI advertisement watcher is unavailable");
        if (state_->requestStartedAt) throw VerificationError(Failure::internalError, "RSSI request already active");
        if (report) state_->reporter = std::move(report);
        state_->samples.beginRequest(std::move(target), started);
        state_->requestStartedAt = started;
        state_->lastRequestStartedAt = started;
        state_->firstCallbackAt = state_->firstTargetMatchAt = state_->firstAcceptedAt = 0;
        state_->callbacks = state_->accepted = state_->addressMismatch = state_->addressTypeMismatch = 0;
        state_->beforeRequest = state_->beforeTarget = state_->stale = state_->outOfOrder = 0;
        state_->invalidSignal = state_->invalidTimestamp = state_->targetUpdates = state_->physicalTargetResets = 0;
        message = "RSSI request armed; watcherAgeMs=" +
            std::to_string(state_->watcherStartedAt && started >= state_->watcherStartedAt ? started - state_->watcherStartedAt : 0);
        notify = state_->reporter;
    }
    if (notify) notify(message);
}

void RssiSampler::updateTarget(ConnectionTarget target) {
    if (!state_) throw VerificationError(Failure::cancelled, "RSSI sampler is not active");
    std::lock_guard lock(state_->mutex);
    const auto previous = state_->samples.evidence(target).target;
    const bool physicalChange = previous.endpointId != target.endpointId || previous.address != target.address ||
        previous.addressType != target.addressType;
    if (state_->samples.updateTarget(std::move(target), GetTickCount64())) {
        ++state_->targetUpdates;
        if (physicalChange) ++state_->physicalTargetResets;
    }
}

RssiEvidence RssiSampler::evidence(const ConnectionTarget& current) const {
    if (!state_) return {Failure::cancelled};
    std::lock_guard lock(state_->mutex);
    return state_->samples.evidence(current);
}

std::string RssiSampler::diagnostics() const {
    if (!state_) return "RSSI diagnostics unavailable: watcher not started";
    std::lock_guard lock(state_->mutex);
    const auto elapsed = [this](std::uint64_t at) {
        return at && state_->lastRequestStartedAt && at >= state_->lastRequestStartedAt
            ? std::to_string(at - state_->lastRequestStartedAt) : std::string("none");
    };
    const auto watcherElapsed = [this](std::uint64_t at) {
        return at && state_->watcherStartedAt && at >= state_->watcherStartedAt
            ? std::to_string(at - state_->watcherStartedAt) : std::string("none");
    };
    return "RSSI stats: watcherAgeAtRequestMs=" +
        std::to_string(state_->lastRequestStartedAt >= state_->watcherStartedAt
            ? state_->lastRequestStartedAt - state_->watcherStartedAt : 0) +
        "; watcherFirstCallbackMs=" + watcherElapsed(state_->firstWatcherCallbackAt) +
        "; watcherFirstTargetMatchMs=" + watcherElapsed(state_->firstWatcherTargetMatchAt) +
        "; watcherCallbacks=" + std::to_string(state_->watcherCallbacks) +
        "; watcherTargetMatches=" + std::to_string(state_->watcherTargetMatches) +
        "; firstCallbackMs=" + elapsed(state_->firstCallbackAt) +
        "; firstTargetMatchMs=" + elapsed(state_->firstTargetMatchAt) +
        "; firstAcceptedMs=" + elapsed(state_->firstAcceptedAt) +
        "; callbacks=" + std::to_string(state_->callbacks) +
        "; accepted=" + std::to_string(state_->accepted) +
        "; addressMismatch=" + std::to_string(state_->addressMismatch) +
        "; addressTypeMismatch=" + std::to_string(state_->addressTypeMismatch) +
        "; beforeRequest=" + std::to_string(state_->beforeRequest) +
        "; beforeTarget=" + std::to_string(state_->beforeTarget) +
        "; stale=" + std::to_string(state_->stale) +
        "; outOfOrder=" + std::to_string(state_->outOfOrder) +
        "; invalidSignal=" + std::to_string(state_->invalidSignal) +
        "; invalidTimestamp=" + std::to_string(state_->invalidTimestamp) +
        "; targetUpdates=" + std::to_string(state_->targetUpdates) +
        "; physicalTargetResets=" + std::to_string(state_->physicalTargetResets);
}

bool RssiSampler::healthy() const {
    if (!state_) return false;
    std::lock_guard lock(state_->mutex);
    return !state_->failed;
}

void RssiSampler::endRequest() {
    if (!state_) return;
    std::lock_guard lock(state_->mutex);
    state_->samples.endRequest();
    state_->requestStartedAt = 0;
}

void RssiSampler::stop() {
    if (!state_) return;
    const auto state = std::move(state_);
    { std::lock_guard lock(state->mutex); state->samples.stop(); state->failed = true; }
    state->received.revoke();
    state->stopped.revoke();
    if (state->watcher) state->watcher.Stop();
}

RssiSampler::~RssiSampler() {
    try { stop(); }
    catch (...) { OutputDebugStringW(L"RSSI sampler cleanup failed\n"); }
}
}
