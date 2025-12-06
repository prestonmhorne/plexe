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
    //=========================================================================
    double radarNoise_;
    std::mt19937 rng_;
    std::normal_distribution<double> radarNoiseDist_;

    // Last known front vehicle state (from BSM)
    double lastBsmSpeed_;
    double lastBsmDistance_;
    double lastBsmAccel_;

    // Last known radar measurements
    double lastRadarSpeed_;
    double lastRadarDistance_;

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

protected:
    virtual void initialize(int stage) override;
    virtual void messageReceived(PlatooningBeacon* pkt, veins::BaseFrame1609_4* frame) override;

    // Simulate radar measurement from SUMO ground truth + noise
    double getRadarDistance();
    double getRadarSpeed();

    // Apply attack to BSM value if attacker is enabled
    double applyAttack(double trueValue, double currentTime, bool& isValid);

    // Parse attack type string to enum
    AttackType parseAttackType(const std::string& type);

public:
    SecureCACCProtocol();
    virtual ~SecureCACCProtocol();
};

} // namespace security
} // namespace plexe

#endif // SECURE_CACC_PROTOCOL_H
