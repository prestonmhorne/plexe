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
//   0 = NONE            - No attack (benign baseline)
//   1 = OFFSET          - Speed offset attack (van der Heijden VNC 2017)
//   2 = ACCEL_OFFSET    - Acceleration offset (van der Heijden VNC 2017)
//   3 = ACCEL_CONSTANT  - Constant fake acceleration (Amoozadeh IEEE CommMag 2015)
//   4 = POSITION_SHIFT  - Position falsification (van der Heijden VNC 2017)
//
// References:
//   [1] van der Heijden, Lukaseder, Kargl, "Analyzing Attacks on Cooperative
//       Adaptive Cruise Control (CACC)", IEEE VNC 2017, pp. 45-52
//   [2] Amoozadeh et al., "Security vulnerabilities of connected vehicle
//       streams and their impact on cooperative driving", IEEE CommMag 2015
//

#ifndef FDI_ATTACK_INJECTOR_H
#define FDI_ATTACK_INJECTOR_H

#include <omnetpp.h>
#include <cmath>
#include <random>

namespace plexe {
namespace security {

using namespace omnetpp;

// FDI Attack type enumeration - All attacks from peer-reviewed literature
enum class AttackType {
    NONE = 0,             // No attack (benign baseline)
    OFFSET = 1,           // Speed offset attack [van der Heijden VNC 2017]
    ACCEL_OFFSET = 2,     // Acceleration offset [van der Heijden VNC 2017]
    ACCEL_CONSTANT = 3,   // Constant fake acceleration [Amoozadeh IEEE CommMag 2015]
    POSITION_SHIFT = 4    // Position falsification [van der Heijden VNC 2017]
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

    // Literature-sourced attack parameters
    double offsetValue_;        // For OFFSET attack - van der Heijden: 50, 100, 150 m/s
    double accelOffset_;        // For ACCEL_OFFSET attack - van der Heijden: -30 to +30 m/s²
    double accelFakeValue_;     // For ACCEL_CONSTANT attack - Amoozadeh: 6 m/s²
    double positionShiftRate_;  // For POSITION_SHIFT attack - van der Heijden: 3-11 m/s

    // Sensor parameters
    double noiseStd_;           // Base sensor noise standard deviation (0.5 m/s per van der Heijden)

    // State tracking
    bool underAttack_;
    double attackStartValue_;

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
          // Literature-standard defaults from van der Heijden VNC 2017 Table I
          offsetValue_(150.0),         // van der Heijden: 150 m/s speed offset
          accelOffset_(-30.0),         // van der Heijden: -30 m/s² (emergency braking)
          accelFakeValue_(6.0),        // Amoozadeh: 6 m/s² acceleration falsification
          positionShiftRate_(7.0),     // van der Heijden: 7 m/s position shift rate
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
    void setOffsetValue(double v) { offsetValue_ = v; }         // van der Heijden: 50, 100, 150 m/s
    void setAccelOffset(double v) { accelOffset_ = v; }         // van der Heijden: -30 to +30 m/s²
    void setAccelFakeValue(double v) { accelFakeValue_ = v; }   // Amoozadeh: 6 m/s²
    void setPositionShiftRate(double v) { positionShiftRate_ = v; } // van der Heijden: 3-11 m/s
    void setNoiseStd(double v) { noiseStd_ = v; }

    // Get the (potentially spoofed) sensor value
    // Implements literature-sourced FDI attacks
    double getValue(double trueValue, double currentTime, bool& isValid) {
        isValid = true;
        double noise = noiseStd_ * normalDist_(rng_);

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

            case AttackType::OFFSET:  // Speed offset attack [van der Heijden VNC 2017]
                // Paper Table I: 50, 100, 150 m/s offset added to true speed
                value = trueValue + offsetValue_ + noise;
                injectedErrorOut_.record(offsetValue_);
                break;

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

            case AttackType::POSITION_SHIFT:  // Position falsification [van der Heijden VNC 2017]
                // Paper: "position error that increases linearly over time"
                // Table I: 3, 5, 7, 9, 11 m/s position shift rate
                {
                    double posShift = positionShiftRate_ * timeSinceAttack;
                    value = trueValue + posShift + noise;
                    injectedErrorOut_.record(posShift);
                }
                break;

            default:
                value = trueValue + noise;
                injectedErrorOut_.record(0);
        }

        return value;
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
            case AttackType::OFFSET: return "OFFSET";
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
    }
};

} // namespace security
} // namespace plexe

#endif // FDI_ATTACK_INJECTOR_H
