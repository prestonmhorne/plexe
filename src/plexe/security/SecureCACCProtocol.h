//
// SecureCACCProtocol.h - Attack-Resilient CACC Protocol
//
// CS 6376 Final Project - Resilient V2V ACC Defense
// Vanderbilt University - Preston Horne
//
// Extends SimplePlatooningBeaconing with:
//   - FDI attack injection capability (for testing)
//   - Hybrid automaton defense with ensemble detection
//   - Simulated radar sensor for cross-validation
//   - Mode-dependent sensor fusion
//

#ifndef SECURE_CACC_PROTOCOL_H
#define SECURE_CACC_PROTOCOL_H

#include "plexe/protocols/SimplePlatooningBeaconing.h"
#include "plexe/security/FDIAttackInjector.h"
#include "plexe/security/HybridAutomatonDefense.h"
#include "plexe/CC_Const.h"

#include <random>

namespace plexe {
namespace security {

using namespace omnetpp;

class SecureCACCProtocol : public SimplePlatooningBeaconing {
private:
    //=========================================================================
    // Attack Injection (for testing/benchmarking)
    //=========================================================================
    bool attackerEnabled_;
    FDIAttackInjector attacker_;           // Speed field attacker
    FDIAttackInjector accelAttacker_;      // Acceleration field attacker
    FDIAttackInjector positionAttacker_;   // Position field attacker

    //=========================================================================
    // Defense Mechanism
    //=========================================================================
    EnsembleDetector detector_;
    ACCHybridAutomaton automaton_;

    //=========================================================================
    // Simulated Radar Sensor
    //
    // Real automotive radar measures:
    // 1. Range (distance to target) via time-of-flight
    // 2. Range-rate (relative velocity) via Doppler shift
    // 3. Azimuth angle (bearing to target)
    //
    // We simulate this by using SUMO ground truth positions/speeds
    // and computing relative measurements with realistic noise.
    //=========================================================================
    double radarNoise_;
    std::mt19937 rng_;
    std::normal_distribution<double> radarNoiseDist_;

    // Own vehicle state (ego vehicle)
    double egoSpeed_;
    double egoAccel_;
    double egoPositionX_;
    double egoPositionY_;

    // Last known front vehicle state (from BSM - potentially attacked)
    double lastBsmSpeed_;
    double lastBsmDistance_;
    double lastBsmAccel_;

    // Last known radar measurements (computed from ground truth)
    double lastRadarSpeed_;          // Absolute speed of front vehicle (derived)
    double lastRadarDistance_;       // Range to front vehicle
    double lastRadarRelativeSpeed_;  // Range-rate (relative velocity)

    // Previous measurements for derivative estimation
    double prevRadarDistance_;
    double prevMeasurementTime_;

    // DoS detection
    int consecutiveDrops_;

    //=========================================================================
    // NED Parameters
    //=========================================================================
    // Defense thresholds
    double positionThreshold_;
    double speedThreshold_;
    double accelThreshold_;
    double kalmanThreshold_;
    double cusumThreshold_;
    double cusumDrift_;
    double hedgingAlpha_;

    // Attack parameters (for testing)
    std::string attackTypeStr_;
    double attackMagnitude_;
    double attackStartTime_;
    double attackDuration_;

    //=========================================================================
    // Output Vectors for Analysis
    //=========================================================================
    cOutVector bsmSpeedOut_;
    cOutVector bsmAccelOut_;
    cOutVector bsmPositionOut_;
    cOutVector radarSpeedOut_;
    cOutVector fusedSpeedOut_;
    cOutVector defenseModeOut_;
    cOutVector detectorVotesOut_;
    cOutVector residualOut_;
    cOutVector attackActiveOut_;
    cOutVector headwayOut_;          // Current headway setting
    cOutVector activeControllerOut_; // 0=driver, 1=ACC, 2=CACC

protected:
    virtual void initialize(int stage) override;
    virtual void messageReceived(PlatooningBeacon* pkt, veins::BaseFrame1609_4* frame) override;

    //=========================================================================
    // Radar Simulation Methods
    //
    // Simulates realistic automotive radar that measures:
    // - Range: distance to front vehicle (time-of-flight)
    // - Range-rate: relative velocity (Doppler shift)
    // - Front vehicle absolute speed: derived from ego speed + range-rate
    //=========================================================================

    // Get radar range measurement (distance to front vehicle)
    // Uses ground truth positions + Gaussian noise (σ = radarNoise_)
    double getRadarRange(double frontPosX, double frontPosY);

    // Get radar range-rate measurement (relative velocity via Doppler)
    // Positive = closing, Negative = separating
    double getRadarRangeRate(double frontSpeed);

    // Derive front vehicle absolute speed from ego speed + range-rate
    // frontSpeed = egoSpeed + rangeRate (when closing, rangeRate > 0)
    double getRadarDerivedSpeed(double rangeRate);

    // Legacy methods (for backwards compatibility)
    double getRadarDistance();
    double getRadarSpeed();

    // Apply attack to BSM value if attacker is enabled
    double applyAttack(double trueValue, double currentTime, bool& isValid);

    // Parse attack type string to enum
    AttackType parseAttackType(const std::string& type);

    // Apply headway adjustment based on defense mode
    // Per Ploeg 2015: CACC h=0.5s, dCACC h=1.24s, ACC h=3.16s
    void applyHeadwayAdjustment();

public:
    SecureCACCProtocol();
    virtual ~SecureCACCProtocol();
};

} // namespace security
} // namespace plexe

#endif // SECURE_CACC_PROTOCOL_H
