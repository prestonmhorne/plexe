//
// FDIAttackInjector.h - False Data Injection Attack Simulator
//
// CS 6376 Final Project - Resilient V2V ACC Defense
// Vanderbilt University - Preston Horne
//
// BSM (Basic Safety Message) sensor with FDI attack injection
// All attacks sourced from peer-reviewed CACC security literature
//
// FDI Attack Types (Literature-Sourced):
//
// Verified attacks used in evaluation:
//   0 = NONE            - No attack (benign baseline)
//   1 = CONSTANT        - Constant fake speed value [van der Heijden VNC 2017]
//   2 = OFFSET          - Speed offset attack [van der Heijden VNC 2017]
//   4 = REPLAY          - Replay old BSM data (3s experimental parameter)
//   6 = ACCEL_OFFSET    - Acceleration offset [van der Heijden VNC 2017]
//   7 = ACCEL_CONSTANT  - Constant fake acceleration [Amoozadeh IEEE CommMag 2015]
//   8 = POSITION_SHIFT  - Position falsification (+30m) [Boddupalli REPLACE 2021]
//
// Deprecated attacks (kept for backwards compatibility):
//   3 = DRIFT           - (unverified in source literature)
//   5 = NOISE           - (unverified in source literature)
//
// References:
//   [1] van der Heijden, Lukaseder, Kargl, "Analyzing Attacks on Cooperative
//       Adaptive Cruise Control (CACC)", IEEE VNC 2017, pp. 45-52
//   [2] Amoozadeh et al., "Security vulnerabilities of connected vehicle
//       streams and their impact on cooperative driving", IEEE CommMag 2015
//   [3] Boddupalli et al., "REPLACE: Real-time security assurance in vehicular
//       platoons against V2V attacks", IEEE ITSC 2021
//

#ifndef FDI_ATTACK_INJECTOR_H
#define FDI_ATTACK_INJECTOR_H

#include <omnetpp.h>
#include <cmath>
#include <random>
#include <deque>

namespace plexe {
namespace security {

using namespace omnetpp;

// FDI Attack type enumeration - All attacks from peer-reviewed literature
enum class AttackType {
    NONE = 0,             // No attack (benign baseline)
    // Speed field attacks
    CONSTANT = 1,         // Constant fake speed [van der Heijden VNC 2017]
    OFFSET = 2,           // Speed offset attack [van der Heijden VNC 2017]
    DRIFT = 3,            // Gradual speed drift/ramp [Amoozadeh IEEE CommMag 2015]
    REPLAY = 4,           // Replay old BSM data [SAE J2735, ETSI ITS-G5]
    NOISE = 5,            // Amplified measurement noise [REPLACE taxonomy]
    // Acceleration field attacks
    ACCEL_OFFSET = 6,     // Acceleration offset [van der Heijden VNC 2017]
    ACCEL_CONSTANT = 7,   // Constant fake acceleration [Amoozadeh IEEE CommMag 2015]
    // Position field attacks
    POSITION_SHIFT = 8    // Position falsification [van der Heijden VNC 2017]
};

// History entry for replay attack
struct HistoryEntry {
    double value;
    double time;
};


//=============================================================================
// FDIAttackInjector - Literature-Based FDI Attack Simulator
//
// Implements FDI attacks from:
//   [1] van der Heijden et al., IEEE VNC 2017 - speed, accel, position attacks
//   [2] Amoozadeh et al., IEEE CommMag 2015 - acceleration falsification
//=============================================================================
class FDIAttackInjector {
private:
    // Attack timing parameters
    double attackTime_;         // When attack starts (seconds)
    AttackType attackType_;     // Attack type
    double attackDuration_;     // Attack duration (inf = permanent)

    // Speed field attack parameters
    double fakeValue_;          // For CONSTANT attack - fixed speed value
    double offsetValue_;        // For OFFSET attack - van der Heijden: 50, 100, 150 m/s
    double driftRate_;          // For DRIFT attack - Amoozadeh: gradual ramp (m/s per second)
    double replayDelay_;        // For REPLAY attack - SAE J2735: message delay (seconds)
    double noiseMultiplier_;    // For NOISE attack - REPLACE: amplification factor (default 10x)

    // Acceleration field attack parameters
    double accelOffset_;        // For ACCEL_OFFSET attack - van der Heijden: -30 to +30 m/s²
    double accelFakeValue_;     // For ACCEL_CONSTANT attack - Amoozadeh: 6 m/s²

    // Position field attack parameters
    double positionShiftRate_;  // For POSITION_SHIFT attack - van der Heijden: 3-11 m/s

    // Sensor parameters
    double noiseStd_;           // Base sensor noise standard deviation (0.5 m/s per van der Heijden)

    // State tracking
    bool underAttack_;
    double attackStartValue_;

    // History buffer for replay attack
    std::deque<HistoryEntry> historyBuffer_;
    static const size_t HISTORY_SIZE = 1000;

    // Random number generation
    std::mt19937 rng_;
    std::normal_distribution<double> normalDist_;

    // Output vectors for logging
    cOutVector attackActiveOut_;
    cOutVector injectedErrorOut_;

public:
    FDIAttackInjector()
        : attackTime_(std::numeric_limits<double>::infinity()),
          attackType_(AttackType::NONE),
          attackDuration_(std::numeric_limits<double>::infinity()),
          // Literature-standard defaults
          fakeValue_(0.0),             // CONSTANT: report stopped (van der Heijden)
          offsetValue_(150.0),         // OFFSET: van der Heijden VNC 2017 Table I
          driftRate_(2.0),             // DRIFT: Amoozadeh - 2 m/s per second ramp
          replayDelay_(3.0),           // REPLAY: 3 second delay (SAE J2735 freshness)
          noiseMultiplier_(10.0),      // NOISE: REPLACE taxonomy - 10x amplification
          accelOffset_(-30.0),         // ACCEL_OFFSET: van der Heijden -30 m/s²
          accelFakeValue_(6.0),        // ACCEL_CONSTANT: Amoozadeh 6 m/s²
          positionShiftRate_(30.0),    // POSITION_SHIFT: Boddupalli REPLACE +30m
          noiseStd_(0.5),              // van der Heijden: σ = 0.5 m/s
          underAttack_(false),
          attackStartValue_(NAN),
          rng_(std::random_device{}()),
          normalDist_(0.0, 1.0) {
        attackActiveOut_.setName("attackActive");
        injectedErrorOut_.setName("injectedError");
    }

    // Configure attack
    void configure(double attackTime, AttackType attackType,
                   double attackDuration = std::numeric_limits<double>::infinity()) {
        attackTime_ = attackTime;
        attackType_ = attackType;
        attackDuration_ = attackDuration;
    }

    // Set attack parameters (literature-sourced values)
    void setFakeValue(double v) { fakeValue_ = v; }             // CONSTANT: fixed speed
    void setOffsetValue(double v) { offsetValue_ = v; }         // OFFSET: van der Heijden 50-150 m/s
    void setDriftRate(double v) { driftRate_ = v; }             // DRIFT: Amoozadeh ramp rate
    void setReplayDelay(double v) { replayDelay_ = v; }         // REPLAY: SAE J2735 delay
    void setNoiseMultiplier(double v) { noiseMultiplier_ = v; } // NOISE: REPLACE amplification
    void setAccelOffset(double v) { accelOffset_ = v; }         // ACCEL_OFFSET: van der Heijden -30 to +30
    void setAccelFakeValue(double v) { accelFakeValue_ = v; }   // ACCEL_CONSTANT: Amoozadeh 6 m/s²
    void setPositionShiftRate(double v) { positionShiftRate_ = v; } // POSITION_SHIFT: van der Heijden 3-11
    void setNoiseStd(double v) { noiseStd_ = v; }

    // Get the (potentially spoofed) sensor value
    // Implements literature-sourced FDI attacks
    double getValue(double trueValue, double currentTime, bool& isValid) {
        isValid = true;
        double noise = noiseStd_ * normalDist_(rng_);

        // Store history for replay attack
        if (historyBuffer_.size() >= HISTORY_SIZE) {
            historyBuffer_.pop_front();
        }
        historyBuffer_.push_back({trueValue, currentTime});

        // Before attack time, return true value
        if (currentTime < attackTime_) {
            attackActiveOut_.record(0);
            return trueValue + noise;
        }

        // Check if attack has ended
        if (currentTime > attackTime_ + attackDuration_) {
            underAttack_ = false;
            attackActiveOut_.record(0);
            return trueValue + noise;
        }

        // Mark attack as active
        if (!underAttack_) {
            underAttack_ = true;
            attackStartValue_ = trueValue;
        }

        attackActiveOut_.record(1);
        double timeSinceAttack = currentTime - attackTime_;
        double value;

        // Apply attack based on type - all from peer-reviewed literature
        switch (attackType_) {
            case AttackType::NONE:  // No attack (baseline)
                value = trueValue + noise;
                injectedErrorOut_.record(0);
                break;

            //=================================================================
            // SPEED FIELD ATTACKS
            //=================================================================

            case AttackType::CONSTANT:  // Constant fake speed [van der Heijden VNC 2017]
                // Attacker reports fixed speed regardless of true value
                // e.g., report 0 m/s (stopped) or any arbitrary value
                value = fakeValue_ + noise;
                injectedErrorOut_.record(std::abs(value - trueValue));
                break;

            case AttackType::OFFSET:  // Speed offset attack [van der Heijden VNC 2017]
                // Paper Table I: 50, 100, 150 m/s offset added to true speed
                value = trueValue + offsetValue_ + noise;
                injectedErrorOut_.record(offsetValue_);
                break;

            case AttackType::DRIFT:  // Gradual speed drift [Amoozadeh IEEE CommMag 2015]
                // Ramp attack: error increases linearly over time
                // Harder to detect than sudden offset
                {
                    double driftAmount = driftRate_ * timeSinceAttack;
                    value = trueValue + driftAmount + noise;
                    injectedErrorOut_.record(driftAmount);
                }
                break;

            case AttackType::REPLAY:  // Replay old BSM data [SAE J2735, ETSI ITS-G5]
                // Attacker records and retransmits old messages
                // Violates BSM freshness requirements (typically 300ms)
                {
                    double targetTime = currentTime - replayDelay_;
                    double replayedVal = getHistoricalValue(targetTime);
                    if (!std::isnan(replayedVal)) {
                        value = replayedVal + noise;
                        injectedErrorOut_.record(std::abs(value - trueValue));
                    } else {
                        value = trueValue + noise;
                        injectedErrorOut_.record(0);
                    }
                }
                break;

            case AttackType::NOISE:  // Amplified measurement noise [REPLACE taxonomy]
                // Attacker injects amplified noise to increase variance
                // Detected by variance detector; evades threshold detector
                {
                    double amplifiedNoise = noiseMultiplier_ * noiseStd_ * normalDist_(rng_);
                    value = trueValue + amplifiedNoise;
                    injectedErrorOut_.record(std::abs(amplifiedNoise));
                }
                break;

            //=================================================================
            // ACCELERATION FIELD ATTACKS
            //=================================================================

            case AttackType::ACCEL_OFFSET:  // Acceleration offset [van der Heijden VNC 2017]
                // Paper Table I: -30, -10, 0, 10, 30 m/s² offset
                // "Most dangerous attack - affects ALL controllers"
                value = trueValue + accelOffset_ + noise * 0.1;
                injectedErrorOut_.record(accelOffset_);
                break;

            case AttackType::ACCEL_CONSTANT:  // Constant fake acceleration [Amoozadeh IEEE CommMag 2015]
                // Paper: "adversary manipulates acceleration field to fixed value"
                // Amoozadeh uses 6 m/s², van der Heijden uses -30 to +30 m/s²
                value = accelFakeValue_ + noise * 0.1;
                injectedErrorOut_.record(std::abs(value - trueValue));
                break;

            //=================================================================
            // POSITION FIELD ATTACKS
            //=================================================================

            case AttackType::POSITION_SHIFT:  // Position falsification [Boddupalli REPLACE 2021]
                // Boddupalli Table II: constant position mutation (+28m, +30m, etc.)
                // Fixed offset attack on BSM position field
                {
                    value = trueValue + positionShiftRate_ + noise;
                    injectedErrorOut_.record(positionShiftRate_);
                }
                break;

            default:
                value = trueValue + noise;
                injectedErrorOut_.record(0);
        }

        return value;
    }

    // Find historical value for replay attack
    double getHistoricalValue(double targetTime) {
        if (historyBuffer_.empty()) return NAN;

        double minDiff = std::numeric_limits<double>::infinity();
        double bestValue = NAN;

        for (const auto& entry : historyBuffer_) {
            double diff = std::abs(entry.time - targetTime);
            if (diff < minDiff && entry.time > 0) {
                minDiff = diff;
                bestValue = entry.value;
            }
        }

        // Only return if we found something within 0.5 seconds
        if (minDiff < 0.5) {
            return bestValue;
        }
        return NAN;
    }

    // Legacy method for backwards compatibility
    double getDistance(double trueDistance, double currentTime) {
        bool valid;
        return getValue(trueDistance, currentTime, valid);
    }

    // Get attack type name
    static const char* getAttackName(AttackType type) {
        switch (type) {
            case AttackType::NONE: return "NONE";
            case AttackType::CONSTANT: return "CONSTANT";
            case AttackType::OFFSET: return "OFFSET";
            case AttackType::DRIFT: return "DRIFT";
            case AttackType::REPLAY: return "REPLAY";
            case AttackType::NOISE: return "NOISE";
            case AttackType::ACCEL_OFFSET: return "ACCEL_OFFSET";
            case AttackType::ACCEL_CONSTANT: return "ACCEL_CONSTANT";
            case AttackType::POSITION_SHIFT: return "POSITION_SHIFT";
            default: return "UNKNOWN";
        }
    }

    const char* getAttackName() const {
        return getAttackName(attackType_);
    }

    bool isUnderAttack() const { return underAttack_; }
    AttackType getAttackType() const { return attackType_; }

    void reset() {
        underAttack_ = false;
        attackStartValue_ = NAN;
        historyBuffer_.clear();
    }
};

} // namespace security
} // namespace plexe

#endif // FDI_ATTACK_INJECTOR_H
