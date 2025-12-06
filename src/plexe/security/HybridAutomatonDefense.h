//
// HybridAutomatonDefense.h - Port of MATLAB ACCHybridAutomaton.m
//
// CS 6376 Final Project - Resilient V2V ACC Defense
// Vanderbilt University - Preston Horne
//
// 4-state hybrid automaton for attack-resilient ACC:
//   - NORMAL: Trust V2V data (q_N)
//   - ATTACK_DETECTED: Confirming attack, blending sensors (q_D)
//   - DEFENSE_ACTIVE: Using local sensors only (q_A)
//   - DEGRADED: Conservative mode when local sensors unreliable (q_F)
//

#ifndef HYBRID_AUTOMATON_DEFENSE_H
#define HYBRID_AUTOMATON_DEFENSE_H

#include <omnetpp.h>
#include <algorithm>
#include <cmath>
#include <vector>
#include <random>

namespace plexe {
namespace security {

using namespace omnetpp;

// Thread-local RNG for probabilistic detection
inline double securityRand() {
    static thread_local std::mt19937 gen(std::random_device{}());
    static thread_local std::uniform_real_distribution<double> dis(0.0, 1.0);
    return dis(gen);
}

// Defense mode enumeration (matches MATLAB ACCHybridAutomaton constants)
enum class DefenseMode {
    NORMAL = 0,           // Trust V2V data
    ATTACK_DETECTED = 1,  // Confirming attack, blending sensors
    DEFENSE_ACTIVE = 2,   // Using local sensors only
    DEGRADED = 3          // Conservative mode
};

//=============================================================================
// ThresholdDetector - Port of ThresholdDetector.m
//=============================================================================
class ThresholdDetector {
private:
    double threshold_;       // Detection threshold (default: 5.0m)
    double detectionProb_;   // Detection probability (default: 0.95)
    bool attackDetected_;
    double detectionTime_;

public:
    ThresholdDetector(double threshold = 5.0, double detectionProb = 0.95)
        : threshold_(threshold), detectionProb_(detectionProb),
          attackDetected_(false), detectionTime_(NAN) {}

    bool check(double v2vValue, double localValue, double currentTime,
               double& confidence, double& anomalyScore) {
        double sensorDiff = std::abs(v2vValue - localValue);
        anomalyScore = sensorDiff / threshold_;

        if (sensorDiff > threshold_) {
            // Probabilistic detection (matches MATLAB: rand() < DetectionProb)
            if (securityRand() < detectionProb_) {
                if (!attackDetected_) {
                    attackDetected_ = true;
                    detectionTime_ = currentTime;
                }
                confidence = std::min(anomalyScore, 1.0);
                return true;
            }
        }

        confidence = 0.0;
        return false;
    }

    void reset() {
        attackDetected_ = false;
        detectionTime_ = NAN;
    }

    double getThreshold() const { return threshold_; }
    void setThreshold(double t) { threshold_ = t; }
};

//=============================================================================
// KalmanDetector - Port of KalmanDetector.m
//=============================================================================
class KalmanDetector {
private:
    double processNoise_;      // Q
    double measurementNoise_;  // R
    double anomalyThreshold_;  // Number of std devs for detection

    double x_est_;             // State estimate
    double P_est_;             // Estimation error covariance
    bool initialized_;

    bool attackDetected_;
    double detectionTime_;

public:
    KalmanDetector(double processNoise = 0.1, double measNoise = 0.5,
                   double anomalyThreshold = 3.0)
        : processNoise_(processNoise), measurementNoise_(measNoise),
          anomalyThreshold_(anomalyThreshold), x_est_(0), P_est_(1.0),
          initialized_(false), attackDetected_(false), detectionTime_(NAN) {}

    bool check(double v2vValue, double localValue, double currentTime,
               double& confidence, double& anomalyScore) {
        // Use local sensor as ground truth for Kalman filter
        double measurement = localValue;

        if (!initialized_) {
            x_est_ = measurement;
            initialized_ = true;
            confidence = 0.0;
            anomalyScore = 0.0;
            return false;
        }

        // Prediction step (simple random walk model)
        double x_pred = x_est_;
        double P_pred = P_est_ + processNoise_;

        // Update step using local measurement
        double K = P_pred / (P_pred + measurementNoise_);  // Kalman gain
        x_est_ = x_pred + K * (measurement - x_pred);
        P_est_ = (1 - K) * P_pred;

        // Calculate innovation (difference between V2V and predicted)
        double innovation = std::abs(v2vValue - x_est_);
        double innovation_std = std::sqrt(P_est_ + measurementNoise_);

        // Normalized anomaly score (number of standard deviations)
        anomalyScore = innovation / std::max(innovation_std, 0.01);

        // Detect if anomaly exceeds threshold
        if (anomalyScore > anomalyThreshold_) {
            if (!attackDetected_) {
                attackDetected_ = true;
                detectionTime_ = currentTime;
            }
            confidence = std::min(anomalyScore / anomalyThreshold_, 1.0);
            return true;
        }

        confidence = 0.0;
        return false;
    }

    void reset() {
        x_est_ = 0;
        P_est_ = 1.0;
        initialized_ = false;
        attackDetected_ = false;
        detectionTime_ = NAN;
    }
};

//=============================================================================
// CUSUMDetector - Port of CUSUMDetector.m
//=============================================================================
class CUSUMDetector {
private:
    double driftThreshold_;     // Expected drift (slack parameter)
    double decisionThreshold_;  // CUSUM decision boundary (h)
    double forgettingFactor_;   // Exponential forgetting

    double cusum_pos_;          // Cumulative sum for positive drift
    double cusum_neg_;          // Cumulative sum for negative drift
    double baseline_;

    bool attackDetected_;
    double detectionTime_;

public:
    CUSUMDetector(double driftThreshold = 2.0, double decisionThreshold = 10.0,
                  double forgettingFactor = 0.95)
        : driftThreshold_(driftThreshold), decisionThreshold_(decisionThreshold),
          forgettingFactor_(forgettingFactor), cusum_pos_(0), cusum_neg_(0),
          baseline_(NAN), attackDetected_(false), detectionTime_(NAN) {}

    bool check(double v2vValue, double localValue, double currentTime,
               double& confidence, double& anomalyScore) {
        // Compute residual (V2V - Local)
        double residual = v2vValue - localValue;

        if (std::isnan(baseline_)) {
            baseline_ = residual;
            confidence = 0.0;
            anomalyScore = 0.0;
            return false;
        }

        // Update CUSUM statistics
        double deviation = residual - baseline_;

        // Two-sided CUSUM with forgetting factor (matches MATLAB exactly)
        cusum_pos_ = std::max(0.0, forgettingFactor_ * cusum_pos_ + deviation - driftThreshold_);
        cusum_neg_ = std::max(0.0, forgettingFactor_ * cusum_neg_ - deviation - driftThreshold_);

        // Anomaly score is max of both directions
        anomalyScore = std::max(cusum_pos_, cusum_neg_);

        // Update baseline slowly (adaptive) - matches MATLAB
        baseline_ = 0.99 * baseline_ + 0.01 * residual;

        // Detect if CUSUM exceeds threshold
        if (anomalyScore > decisionThreshold_) {
            if (!attackDetected_) {
                attackDetected_ = true;
                detectionTime_ = currentTime;
            }
            confidence = std::min(anomalyScore / decisionThreshold_, 1.0);
            return true;
        }

        confidence = 0.0;
        return false;
    }

    void reset() {
        cusum_pos_ = 0.0;
        cusum_neg_ = 0.0;
        baseline_ = NAN;
        attackDetected_ = false;
        detectionTime_ = NAN;
    }

    void setDecisionThreshold(double threshold) { decisionThreshold_ = threshold; }
    double getCusumValue() const { return std::max(cusum_pos_, cusum_neg_); }
};

//=============================================================================
// ReplayDetector - Detects replay attacks via timestamp freshness checking
//
// Primary method: Timestamp freshness - BSMs contain a timestamp field.
// If the BSM timestamp is older than maxFreshness_ (e.g., 0.5s), the message
// is stale and likely a replay attack. This is the standard defense per
// SAE J2735 and ETSI ITS-G5 security guidelines.
//
// Secondary method: Cross-correlation analysis for cases where timestamps
// might be forged. Detects when V2V data correlates with delayed local data.
//=============================================================================
class ReplayDetector {
private:
    // Circular buffer for historical values (secondary method)
    static const int HISTORY_SIZE = 50;  // 5 seconds at 10Hz
    std::vector<double> v2vHistory_;
    std::vector<double> localHistory_;
    std::vector<double> timeHistory_;
    int historyIndex_;
    bool historyFull_;

    // Timestamp freshness parameters (primary method)
    double maxFreshness_;         // Maximum acceptable BSM age (seconds)

    // Cross-correlation parameters (secondary method)
    double replayDelayToDetect_;  // Expected replay delay (seconds)
    double correlationThreshold_; // Threshold for detection
    int consecutiveDetections_;
    int detectionThreshold_;

    bool attackDetected_;
    double detectionTime_;

    // Calculate cross-correlation at given lag
    double crossCorrelation(int lag) const {
        if (lag >= HISTORY_SIZE || lag < 0) return 0.0;

        double sumXY = 0.0, sumX = 0.0, sumY = 0.0;
        double sumX2 = 0.0, sumY2 = 0.0;
        int n = 0;

        for (int i = lag; i < HISTORY_SIZE; i++) {
            int j = (historyIndex_ + i) % HISTORY_SIZE;
            int k = (historyIndex_ + i - lag) % HISTORY_SIZE;

            double x = v2vHistory_[j];
            double y = localHistory_[k];  // Local at lag samples earlier

            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumX2 += x * x;
            sumY2 += y * y;
            n++;
        }

        if (n < 10) return 0.0;

        double meanX = sumX / n;
        double meanY = sumY / n;
        double varX = sumX2 / n - meanX * meanX;
        double varY = sumY2 / n - meanY * meanY;

        if (varX < 1e-9 || varY < 1e-9) return 0.0;

        double cov = sumXY / n - meanX * meanY;
        return cov / std::sqrt(varX * varY);
    }

    // Calculate real-time correlation between V2V and local changes
    double instantCorrelation() const {
        // Compare recent micro-variations: do V2V changes track local changes?
        const int windowSize = 10;  // 1 second window
        if (!historyFull_) return 1.0;  // Assume correlated until we have data

        double sumProduct = 0.0;
        double sumV2V2 = 0.0, sumLocal2 = 0.0;

        for (int i = 1; i < windowSize; i++) {
            int curr = (historyIndex_ + HISTORY_SIZE - i) % HISTORY_SIZE;
            int prev = (historyIndex_ + HISTORY_SIZE - i - 1) % HISTORY_SIZE;

            double deltaV2V = v2vHistory_[curr] - v2vHistory_[prev];
            double deltaLocal = localHistory_[curr] - localHistory_[prev];

            sumProduct += deltaV2V * deltaLocal;
            sumV2V2 += deltaV2V * deltaV2V;
            sumLocal2 += deltaLocal * deltaLocal;
        }

        if (sumV2V2 < 1e-9 || sumLocal2 < 1e-9) return 1.0;  // No variation
        return sumProduct / std::sqrt(sumV2V2 * sumLocal2);
    }

public:
    ReplayDetector(double maxFreshness = 0.5, double replayDelay = 3.0,
                   double corrThreshold = 0.6, int detThreshold = 3)
        : historyIndex_(0), historyFull_(false),
          maxFreshness_(maxFreshness),
          replayDelayToDetect_(replayDelay), correlationThreshold_(corrThreshold),
          consecutiveDetections_(0), detectionThreshold_(detThreshold),
          attackDetected_(false), detectionTime_(NAN) {
        v2vHistory_.resize(HISTORY_SIZE, 0.0);
        localHistory_.resize(HISTORY_SIZE, 0.0);
        timeHistory_.resize(HISTORY_SIZE, 0.0);
    }

    // Primary check: timestamp freshness
    // Immediate detection if BSM age > maxFreshness_ (e.g., 0.5s)
    // For a 3-second replay, age = 3s >> 0.5s, so detect immediately
    bool checkTimestamp(double bsmTimestamp, double currentTime,
                        double& confidence, double& anomalyScore) {
        double age = currentTime - bsmTimestamp;

        if (age > maxFreshness_) {
            // BSM is stale - replay attack detected immediately
            anomalyScore = age / maxFreshness_;  // How many times over threshold
            confidence = std::min(anomalyScore, 1.0);

            if (!attackDetected_) {
                attackDetected_ = true;
                detectionTime_ = currentTime;
            }
            return true;  // Immediate detection, no consecutive threshold needed
        } else {
            anomalyScore = age / maxFreshness_;
            confidence = 0.0;
        }
        return false;
    }

    // Secondary check: cross-correlation (fallback if timestamps are forged)
    bool check(double v2vValue, double localValue, double currentTime,
               double& confidence, double& anomalyScore) {
        // Store current values in circular buffer
        v2vHistory_[historyIndex_] = v2vValue;
        localHistory_[historyIndex_] = localValue;
        timeHistory_[historyIndex_] = currentTime;

        historyIndex_ = (historyIndex_ + 1) % HISTORY_SIZE;
        if (historyIndex_ == 0) historyFull_ = true;

        // Need full history for correlation-based detection
        if (!historyFull_) {
            confidence = 0.0;
            anomalyScore = 0.0;
            return false;
        }

        // Check cross-correlation at replay delay lag
        int lagSamples = static_cast<int>(replayDelayToDetect_ * 10);  // 10Hz sampling
        double corrAtLag = crossCorrelation(lagSamples);
        double corrAtZero = crossCorrelation(0);
        double lagExcess = corrAtLag - corrAtZero;

        // Check instant correlation of micro-variations
        double instantCorr = instantCorrelation();

        bool suspiciousLag = lagExcess > 0.2;
        bool suspiciousInstant = instantCorr < 0.3;

        anomalyScore = std::max(lagExcess, (1.0 - instantCorr)) / correlationThreshold_;

        if (suspiciousLag || suspiciousInstant) {
            confidence = std::min(anomalyScore, 1.0);
            return true;
        }

        confidence = 0.0;
        return false;
    }

    void reset() {
        historyIndex_ = 0;
        historyFull_ = false;
        consecutiveDetections_ = 0;
        attackDetected_ = false;
        detectionTime_ = NAN;
        std::fill(v2vHistory_.begin(), v2vHistory_.end(), 0.0);
        std::fill(localHistory_.begin(), localHistory_.end(), 0.0);
        std::fill(timeHistory_.begin(), timeHistory_.end(), 0.0);
    }
};

//=============================================================================
// DoSDetector - Detects denial of service via packet loss rate monitoring
//
// NOTE: This detector is NOT part of the FDI defense ensemble. DoS/jamming is
// an AVAILABILITY attack (drops messages) rather than a False Data Injection
// attack (manipulates message content). It is kept here for potential future
// use but is explicitly excluded from the paper's FDI detection scope.
//
// Key insight: DoS attacks (jamming) cause high packet loss rates.
// We track the ratio of received packets to expected packets over a
// sliding window. If loss rate exceeds threshold, declare DoS.
//
// Compatible interface with other detectors (check method).
//=============================================================================
class DoSDetector {
private:
    double lastPacketTime_;
    double expectedInterval_;   // Expected time between packets (0.1s for 10Hz)
    double windowDuration_;     // Sliding window duration (seconds)

    // Packet tracking in sliding window
    std::vector<double> packetTimes_;
    double windowStart_;

    // Detection thresholds
    double lossRateThreshold_;  // Trigger if loss rate exceeds this (e.g., 0.5 = 50%)
    int minExpectedPackets_;    // Minimum packets expected before checking

    int consecutiveHighLoss_;
    int detectionThreshold_;

    bool attackDetected_;
    double detectionTime_;

public:
    DoSDetector(double expectedInterval = 0.1, double windowDuration = 2.0,
                double lossRateThreshold = 0.5, int detectionThreshold = 5)
        : lastPacketTime_(NAN), expectedInterval_(expectedInterval),
          windowDuration_(windowDuration), windowStart_(0.0),
          lossRateThreshold_(lossRateThreshold),
          minExpectedPackets_(static_cast<int>(windowDuration / expectedInterval)),
          consecutiveHighLoss_(0), detectionThreshold_(detectionThreshold),
          attackDetected_(false), detectionTime_(NAN) {}

    // Unified check interface - call this each time a packet is (or should be) received
    bool check(double v2vValue, double localValue, double currentTime,
               double& confidence, double& anomalyScore) {
        // Remove old packets outside the window
        double windowEnd = currentTime;
        windowStart_ = currentTime - windowDuration_;

        auto it = packetTimes_.begin();
        while (it != packetTimes_.end() && *it < windowStart_) {
            it = packetTimes_.erase(it);
        }

        // Record this packet arrival
        // Note: v2vValue being NaN indicates no packet received this cycle
        bool packetReceived = !std::isnan(v2vValue);
        if (packetReceived) {
            packetTimes_.push_back(currentTime);
            lastPacketTime_ = currentTime;
        }

        // Calculate expected vs actual packets in window
        int expectedPackets = static_cast<int>(windowDuration_ / expectedInterval_);
        int actualPackets = static_cast<int>(packetTimes_.size());

        // Need minimum history before detecting
        if (currentTime < windowDuration_) {
            confidence = 0.0;
            anomalyScore = 0.0;
            return false;
        }

        // Calculate loss rate
        double lossRate = 1.0 - (static_cast<double>(actualPackets) / expectedPackets);
        lossRate = std::max(0.0, std::min(1.0, lossRate));

        anomalyScore = lossRate / lossRateThreshold_;

        // Check if loss rate exceeds threshold
        if (lossRate > lossRateThreshold_) {
            consecutiveHighLoss_++;
        } else {
            consecutiveHighLoss_ = std::max(0, consecutiveHighLoss_ - 1);
        }

        if (consecutiveHighLoss_ >= detectionThreshold_) {
            if (!attackDetected_) {
                attackDetected_ = true;
                detectionTime_ = currentTime;
            }
            confidence = std::min(anomalyScore, 1.0);
            return true;
        }

        confidence = 0.0;
        return false;
    }

    void reset() {
        lastPacketTime_ = NAN;
        packetTimes_.clear();
        windowStart_ = 0.0;
        consecutiveHighLoss_ = 0;
        attackDetected_ = false;
        detectionTime_ = NAN;
    }

    double getLossRate() const {
        int expectedPackets = static_cast<int>(windowDuration_ / expectedInterval_);
        int actualPackets = static_cast<int>(packetTimes_.size());
        if (expectedPackets == 0) return 0.0;
        return 1.0 - (static_cast<double>(actualPackets) / expectedPackets);
    }
};

//=============================================================================
// VarianceDetector - Detects noise injection via abnormal variance
//=============================================================================
class VarianceDetector {
private:
    double windowSize_;         // Number of samples in sliding window
    std::vector<double> residualHistory_;
    double baselineVariance_;
    double varianceThreshold_;  // Multiplier for baseline variance (paper: k=1.8)
    bool baselineSet_;
    int baselineSamples_;
    bool attackDetected_;
    double detectionTime_;

public:
    // Paper Eq. 15: k = 1.8 (variance multiplier threshold)
    // Tuned to detect 10x noise attacks even when baseline is contaminated
    VarianceDetector(int windowSize = 20, double varianceThreshold = 1.8)
        : windowSize_(windowSize), baselineVariance_(0.0),
          varianceThreshold_(varianceThreshold), baselineSet_(false),
          baselineSamples_(0), attackDetected_(false), detectionTime_(NAN) {}

    bool check(double v2vValue, double localValue, double currentTime,
               double& confidence, double& anomalyScore) {
        double residual = v2vValue - localValue;

        // Add to history
        residualHistory_.push_back(residual);
        if (residualHistory_.size() > windowSize_) {
            residualHistory_.erase(residualHistory_.begin());
        }

        // Need enough samples
        if (residualHistory_.size() < windowSize_ / 2) {
            confidence = 0.0;
            anomalyScore = 0.0;
            return false;
        }

        // Calculate current variance
        double mean = 0.0;
        for (double r : residualHistory_) mean += r;
        mean /= residualHistory_.size();

        double variance = 0.0;
        for (double r : residualHistory_) {
            variance += (r - mean) * (r - mean);
        }
        variance /= residualHistory_.size();

        // Establish baseline during first samples
        if (!baselineSet_ && baselineSamples_ < 50) {
            baselineVariance_ = (baselineVariance_ * baselineSamples_ + variance) / (baselineSamples_ + 1);
            baselineSamples_++;
            if (baselineSamples_ >= 50) {
                baselineSet_ = true;
                baselineVariance_ = std::max(baselineVariance_, 0.1); // Minimum baseline
            }
            confidence = 0.0;
            anomalyScore = 0.0;
            return false;
        }

        // Check if variance exceeds threshold
        anomalyScore = variance / baselineVariance_;

        if (anomalyScore > varianceThreshold_) {
            if (!attackDetected_) {
                attackDetected_ = true;
                detectionTime_ = currentTime;
            }
            confidence = std::min((anomalyScore - varianceThreshold_) / varianceThreshold_, 1.0);
            return true;
        }

        confidence = 0.0;
        return false;
    }

    void reset() {
        residualHistory_.clear();
        baselineVariance_ = 0.0;
        baselineSet_ = false;
        baselineSamples_ = 0;
        attackDetected_ = false;
        detectionTime_ = NAN;
    }
};

//=============================================================================
// EnsembleDetector - 5 detectors (4 original + replay) for FDI attacks
//
// Paper Eq. 17: Φ_ensemble(t) = 1_{φ_thresh + φ_obs + φ_cusum + φ_var + φ_replay >= 2}
//
// IMPROVEMENT: Added ReplayDetector to overcome the steady-state replay limitation.
// The replay detector uses cross-correlation analysis to detect temporal misalignment
// between BSM and radar data. During transient maneuvers (speed changes), replayed
// BSM values will decorrelate from current radar readings, enabling detection.
//
// SCOPE: This ensemble detects False Data Injection (FDI) attacks that
// manipulate BSM content. It does NOT detect:
//   - DoS/Denial attacks (availability attacks outside FDI scope - drop messages
//     rather than inject false data; no residuals to compare)
//
// DoS limitation is documented in Section V-B of the paper.
//=============================================================================
class EnsembleDetector {
public:
    enum VotingStrategy { VOTE_ANY = 1, VOTE_MAJORITY = 2, VOTE_ALL = 5 };

private:
    // 5 detectors: 4 residual-based + 1 temporal consistency detector
    ThresholdDetector thresholdDet_;    // Eq. 10: instantaneous residual
    KalmanDetector kalmanDet_;          // Eq. 11: observer-based
    CUSUMDetector cusumDet_;            // Eq. 13-14: sequential change detection
    VarianceDetector varianceDet_;      // Eq. 15: noise injection detection
    ReplayDetector replayDet_;          // NEW: cross-correlation for replay detection

    VotingStrategy votingStrategy_;

    bool attackDetected_;
    double detectionTime_;
    std::string triggeringDetector_;

public:
    EnsembleDetector(VotingStrategy strategy = VOTE_MAJORITY)
        : votingStrategy_(strategy), attackDetected_(false),
          detectionTime_(NAN), triggeringDetector_("") {}

    void configure(double thresholdLimit, double kalmanAnomalyThresh,
                   double cusumDecisionThresh) {
        thresholdDet_.setThreshold(thresholdLimit);
        cusumDet_.setDecisionThreshold(cusumDecisionThresh);
    }

    bool check(double v2vValue, double localValue, double currentTime,
               double& confidence, double& anomalyScore, int& votes,
               double bsmTimestamp = -1.0) {
        double conf1, conf2, conf3, conf4, conf5;
        double score1, score2, score3, score4, score5;

        // Run all 5 detectors (4 original + replay)
        bool det1 = thresholdDet_.check(v2vValue, localValue, currentTime, conf1, score1);
        bool det2 = kalmanDet_.check(v2vValue, localValue, currentTime, conf2, score2);
        bool det3 = cusumDet_.check(v2vValue, localValue, currentTime, conf3, score3);
        bool det4 = varianceDet_.check(v2vValue, localValue, currentTime, conf4, score4);

        // Replay detection: use timestamp freshness (primary) if available,
        // otherwise fall back to cross-correlation (secondary)
        bool det5 = false;
        bool replayTimestampDetection = false;  // Track if timestamp-based detection fired
        if (bsmTimestamp > 0) {
            // Primary: timestamp freshness check - immediate detection
            det5 = replayDet_.checkTimestamp(bsmTimestamp, currentTime, conf5, score5);
            replayTimestampDetection = det5;  // Authoritative if timestamp is stale
        }
        if (!det5) {
            // Secondary: cross-correlation for forged timestamps
            det5 = replayDet_.check(v2vValue, localValue, currentTime, conf5, score5);
        }

        // Count votes from 5 detectors (modified Eq. 12 to include replay)
        votes = (det1 ? 1 : 0) + (det2 ? 1 : 0) + (det3 ? 1 : 0) + (det4 ? 1 : 0) + (det5 ? 1 : 0);

        // Timestamp-based replay detection is authoritative - stale timestamps are
        // definitive evidence of replay attack, bypass voting threshold
        if (replayTimestampDetection) {
            votes = 2;  // Force voting threshold to be met
        }

        // Apply voting strategy - 2-of-5 threshold voting
        // Rationale: Heterogeneous detectors target different attack types;
        // requiring 3+ agreement would miss specialized attacks (e.g., replay)
        bool detected = false;
        switch (votingStrategy_) {
            case VOTE_ANY:
                detected = votes >= 1;
                break;
            case VOTE_MAJORITY:
                detected = votes >= 2;  // 2-of-5 threshold (not true majority)
                break;
            case VOTE_ALL:
                detected = votes == 5;
                break;
        }

        // Combined metrics
        if (detected) {
            confidence = std::max({conf1, conf2, conf3, conf4, conf5});
        } else {
            confidence = 0.0;
        }
        anomalyScore = std::max({score1, score2, score3, score4, score5});

        // Record first detection and which detector triggered
        if (detected && !attackDetected_) {
            attackDetected_ = true;
            detectionTime_ = currentTime;
            if (det1) triggeringDetector_ = "threshold";
            else if (det2) triggeringDetector_ = "kalman";
            else if (det3) triggeringDetector_ = "cusum";
            else if (det4) triggeringDetector_ = "variance";
            else if (det5) triggeringDetector_ = "replay";
        }

        return detected;
    }

    void reset() {
        thresholdDet_.reset();
        kalmanDet_.reset();
        cusumDet_.reset();
        varianceDet_.reset();
        replayDet_.reset();
        attackDetected_ = false;
        detectionTime_ = NAN;
        triggeringDetector_ = "";
    }

    double getDetectionTime() const { return detectionTime_; }
    std::string getTriggeringDetector() const { return triggeringDetector_; }
};

//=============================================================================
// ACCHybridAutomaton - Port of ACCHybridAutomaton.m
//=============================================================================
class ACCHybridAutomaton {
private:
    DefenseMode currentMode_;
    double modeEntryTime_;

    // Timing parameters (matches MATLAB properties)
    double confirmationTime_;          // Time to confirm attack before mode switch
    double transitionDelay_;           // Delay for mode transitions
    double localSensorTrustThreshold_; // Min confidence to trust local sensor

    // Detection confirmation state
    int consecutiveDetections_;
    double detectionStartTime_;

    // Pending transition
    DefenseMode pendingTransition_;
    double pendingTransitionTime_;
    bool hasPendingTransition_;

    // Output vectors for logging
    cOutVector modeOut_;
    cOutVector detectedOut_;

public:
    ACCHybridAutomaton(double confirmationTime = 0.3,
                       double transitionDelay = 0.2,
                       double sensorTrustThreshold = 0.5)
        : currentMode_(DefenseMode::NORMAL), modeEntryTime_(0),
          confirmationTime_(confirmationTime), transitionDelay_(transitionDelay),
          localSensorTrustThreshold_(sensorTrustThreshold),
          consecutiveDetections_(0), detectionStartTime_(NAN),
          hasPendingTransition_(false) {
        modeOut_.setName("defenseMode");
        detectedOut_.setName("attackDetected");
    }

    void transition(bool attackDetected, double currentTime,
                    double localSensorConfidence = 1.0) {
        DefenseMode oldMode = currentMode_;

        // Handle pending transitions (delayed mode switches)
        if (hasPendingTransition_ && currentTime >= pendingTransitionTime_) {
            currentMode_ = pendingTransition_;
            modeEntryTime_ = currentTime;
            hasPendingTransition_ = false;
        }

        // State-specific transition logic (matches MATLAB switch statement exactly)
        switch (currentMode_) {
            case DefenseMode::NORMAL:
                if (attackDetected) {
                    // Start detection confirmation
                    if (std::isnan(detectionStartTime_)) {
                        detectionStartTime_ = currentTime;
                    }
                    consecutiveDetections_++;

                    // Require sustained detection for confirmationTime
                    if ((currentTime - detectionStartTime_) >= confirmationTime_) {
                        currentMode_ = DefenseMode::ATTACK_DETECTED;
                        modeEntryTime_ = currentTime;
                    }
                } else {
                    // Reset detection counter
                    consecutiveDetections_ = 0;
                    detectionStartTime_ = NAN;
                }
                break;

            case DefenseMode::ATTACK_DETECTED:
                // Schedule transition to defense with delay
                if (!hasPendingTransition_) {
                    if (localSensorConfidence >= localSensorTrustThreshold_) {
                        pendingTransition_ = DefenseMode::DEFENSE_ACTIVE;
                    } else {
                        pendingTransition_ = DefenseMode::DEGRADED;
                    }
                    pendingTransitionTime_ = currentTime + transitionDelay_;
                    hasPendingTransition_ = true;
                }
                break;

            case DefenseMode::DEFENSE_ACTIVE:
                // Check if local sensor becomes unreliable
                if (localSensorConfidence < localSensorTrustThreshold_) {
                    currentMode_ = DefenseMode::DEGRADED;
                    modeEntryTime_ = currentTime;
                }
                break;

            case DefenseMode::DEGRADED:
                // Recovery logic
                if (localSensorConfidence >= localSensorTrustThreshold_ && attackDetected) {
                    // Can return to DEFENSE_ACTIVE if local sensor recovers
                    pendingTransition_ = DefenseMode::DEFENSE_ACTIVE;
                    pendingTransitionTime_ = currentTime + transitionDelay_;
                    hasPendingTransition_ = true;
                } else if (!attackDetected) {
                    // Attack stopped - can return to NORMAL
                    pendingTransition_ = DefenseMode::NORMAL;
                    pendingTransitionTime_ = currentTime + transitionDelay_;
                    hasPendingTransition_ = true;
                }
                break;
        }

        // Record for output
        modeOut_.record(static_cast<int>(currentMode_));
        detectedOut_.record(attackDetected ? 1 : 0);

        // Log transition
        if (oldMode != currentMode_) {
            EV_INFO << "Mode transition: " << getModeString(oldMode)
                    << " -> " << getModeString(currentMode_)
                    << " at t=" << currentTime << "\n";
        }
    }

    double fuseSensors(double v2vValue, double localValue) {
        // Compute fused sensor value based on current mode
        // (matches MATLAB ACCHybridAutomaton.fuseSensors exactly)
        switch (currentMode_) {
            case DefenseMode::NORMAL:
                // Trust V2V data
                return v2vValue;

            case DefenseMode::ATTACK_DETECTED:
                // Blend sensors (50/50) during confirmation
                return 0.5 * localValue + 0.5 * v2vValue;

            case DefenseMode::DEFENSE_ACTIVE:
                // Use local sensor only
                return localValue;

            case DefenseMode::DEGRADED:
                // Conservative: use minimum (closer = safer assumption)
                // with safety margin
                return std::min(v2vValue, localValue) * 0.9;

            default:
                return localValue;
        }
    }

    bool isUnderAttack() const {
        return currentMode_ != DefenseMode::NORMAL;
    }

    DefenseMode getMode() const { return currentMode_; }

    static const char* getModeString(DefenseMode mode) {
        switch (mode) {
            case DefenseMode::NORMAL: return "NORMAL";
            case DefenseMode::ATTACK_DETECTED: return "ATTACK_DETECTED";
            case DefenseMode::DEFENSE_ACTIVE: return "DEFENSE_ACTIVE";
            case DefenseMode::DEGRADED: return "DEGRADED";
            default: return "UNKNOWN";
        }
    }

    const char* getModeString() const {
        return getModeString(currentMode_);
    }

    void reset() {
        currentMode_ = DefenseMode::NORMAL;
        modeEntryTime_ = 0;
        consecutiveDetections_ = 0;
        detectionStartTime_ = NAN;
        hasPendingTransition_ = false;
    }
};

} // namespace security
} // namespace plexe

#endif // HYBRID_AUTOMATON_DEFENSE_H
