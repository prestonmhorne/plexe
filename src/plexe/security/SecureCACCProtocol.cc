//
// SecureCACCProtocol.cc - Attack-Resilient CACC Protocol Implementation
//
// CS 6376 Final Project - Resilient V2V ACC Defense
// Vanderbilt University - Preston Horne
//

#include "plexe/security/SecureCACCProtocol.h"
#include "plexe/PlexeManager.h"
#include "veins/base/utils/FindModule.h"

using namespace veins;

namespace plexe {
namespace security {

Define_Module(SecureCACCProtocol);

SecureCACCProtocol::SecureCACCProtocol()
    : attackerEnabled_(false),
      radarNoise_(0.5),
      rng_(std::random_device{}()),
      radarNoiseDist_(0.0, 0.5),
      lastBsmSpeed_(0),
      lastBsmDistance_(0),
      lastBsmAccel_(0),
      lastRadarSpeed_(0),
      lastRadarDistance_(0),
      consecutiveDrops_(0),
      positionThreshold_(5.0),
      speedThreshold_(3.0),
      accelThreshold_(4.0),
      kalmanThreshold_(7.815),
      cusumThreshold_(5.0),
      cusumDrift_(2.0),
      hedgingAlpha_(0.5),
      attackMagnitude_(0),
      attackStartTime_(10.0),
      attackDuration_(-1)
{
    // Set output vector names
    bsmSpeedOut_.setName("bsmSpeed");
    bsmAccelOut_.setName("bsmAccel");
    bsmPositionOut_.setName("bsmPosition");
    radarSpeedOut_.setName("radarSpeed");
    fusedSpeedOut_.setName("fusedSpeed");
    defenseModeOut_.setName("defenseMode");
    detectorVotesOut_.setName("detectorVotes");
    residualOut_.setName("detectionResidual");
    attackActiveOut_.setName("attackActive");
}

SecureCACCProtocol::~SecureCACCProtocol()
{
}

void SecureCACCProtocol::initialize(int stage)
{
    SimplePlatooningBeaconing::initialize(stage);

    if (stage == 0) {
        // Read defense parameters from NED
        positionThreshold_ = par("positionThreshold").doubleValue();
        speedThreshold_ = par("speedThreshold").doubleValue();
        accelThreshold_ = par("accelThreshold").doubleValue();
        kalmanThreshold_ = par("kalmanThreshold").doubleValue();
        cusumThreshold_ = par("cusumThreshold").doubleValue();
        cusumDrift_ = par("cusumDrift").doubleValue();
        hedgingAlpha_ = par("hedgingAlpha").doubleValue();
        radarNoise_ = par("radarNoise").doubleValue();

        // Configure radar noise distribution
        radarNoiseDist_ = std::normal_distribution<double>(0.0, radarNoise_);

        // Configure ensemble detector thresholds
        // Paper Eq. 10: τ_th = 3 m/s (speedThreshold_)
        detector_.configure(speedThreshold_, kalmanThreshold_, cusumThreshold_);

        // Read attack parameters
        attackerEnabled_ = par("attackerEnabled").boolValue();
        if (attackerEnabled_) {
            attackTypeStr_ = par("attackType").stdstringValue();
            attackMagnitude_ = par("attackMagnitude").doubleValue();
            attackStartTime_ = par("attackStartTime").doubleValue();
            attackDuration_ = par("attackDuration").doubleValue();

            // Configure the attacker
            AttackType attackType = parseAttackType(attackTypeStr_);
            double duration = (attackDuration_ < 0) ?
                std::numeric_limits<double>::infinity() : attackDuration_;

            attacker_.configure(attackStartTime_, attackType, duration);

            // Set attack-specific parameters (all from peer-reviewed literature)
            switch (attackType) {
                case AttackType::OFFSET:
                    // van der Heijden VNC 2017: speed offset attack (50, 100, 150 m/s)
                    attacker_.setOffsetValue(attackMagnitude_);
                    break;
                case AttackType::ACCEL_OFFSET:
                    // van der Heijden VNC 2017: acceleration offset (-30 to +30 m/s^2)
                    accelAttacker_.configure(attackStartTime_, attackType, duration);
                    accelAttacker_.setAccelOffset(attackMagnitude_);
                    break;
                case AttackType::ACCEL_CONSTANT:
                    // Amoozadeh IEEE CommMag 2015: constant acceleration falsification (6 m/s^2)
                    accelAttacker_.configure(attackStartTime_, attackType, duration);
                    accelAttacker_.setAccelFakeValue(attackMagnitude_);
                    break;
                case AttackType::POSITION_SHIFT:
                    // van der Heijden VNC 2017: position falsification (3-11 m/s shift rate)
                    positionAttacker_.configure(attackStartTime_, attackType, duration);
                    positionAttacker_.setPositionShiftRate(attackMagnitude_);
                    break;
                default:
                    break;
            }

            EV_INFO << "SecureCACCProtocol: Attack configured - type="
                    << attackTypeStr_ << ", magnitude=" << attackMagnitude_
                    << ", start=" << attackStartTime_ << "s\n";
        }
    }
}

AttackType SecureCACCProtocol::parseAttackType(const std::string& type)
{
    // All attacks from peer-reviewed CACC security literature
    if (type == "none") return AttackType::NONE;
    if (type == "offset") return AttackType::OFFSET;           // van der Heijden VNC 2017
    if (type == "accel_offset") return AttackType::ACCEL_OFFSET;     // van der Heijden VNC 2017
    if (type == "accel_constant") return AttackType::ACCEL_CONSTANT; // Amoozadeh IEEE CommMag 2015
    if (type == "position_shift") return AttackType::POSITION_SHIFT; // van der Heijden VNC 2017
    return AttackType::NONE;
}

double SecureCACCProtocol::applyAttack(double trueValue, double currentTime, bool& isValid)
{
    if (!attackerEnabled_) {
        isValid = true;
        return trueValue;
    }
    return attacker_.getValue(trueValue, currentTime, isValid);
}

double SecureCACCProtocol::getRadarDistance()
{
    // Simulated radar - returns the last known BSM distance with noise
    // In a real implementation, this would come from actual radar hardware
    // Here we simulate it by using our own vehicle's perception + noise

    VEHICLE_DATA myData;
    plexeTraciVehicle->getVehicleData(&myData);

    // Use radar range data from Plexe if available, otherwise estimate
    double radarDist = lastBsmDistance_;

    // Add radar noise
    radarDist += radarNoiseDist_(rng_);

    return std::max(0.0, radarDist);
}

double SecureCACCProtocol::getRadarSpeed()
{
    // Simulated radar - for speed we use own vehicle data as ground truth
    // Real radar would measure relative velocity

    VEHICLE_DATA myData;
    plexeTraciVehicle->getVehicleData(&myData);

    // Return own speed with small noise as "radar truth"
    double speed = myData.speed + radarNoiseDist_(rng_) * 0.3;

    return std::max(0.0, speed);
}

void SecureCACCProtocol::messageReceived(PlatooningBeacon* pkt, BaseFrame1609_4* frame)
{
    // Call parent implementation
    SimplePlatooningBeaconing::messageReceived(pkt, frame);

    double currentTime = simTime().dbl();

    // Get the true BSM data from the beacon (this is ground truth from SUMO)
    double trueBsmSpeed = pkt->getSpeed();
    double trueBsmAccel = pkt->getAcceleration();
    double trueBsmPosition = pkt->getPositionX();
    double bsmTimestamp = pkt->getTime();  // BSM timestamp for replay detection

    // Get BSM data (potentially attacked)
    bool bsmValid = true;
    bool accelValid = true;
    bool positionValid = true;

    // Apply speed offset attack (van der Heijden VNC 2017)
    double bsmSpeed = applyAttack(trueBsmSpeed, currentTime, bsmValid);

    // Acceleration attacks (van der Heijden VNC 2017, Amoozadeh IEEE CommMag 2015)
    // Per van der Heijden: "manipulation of the transmitted acceleration...affects all controllers"
    double bsmAccel = trueBsmAccel;
    if (attackerEnabled_ && accelAttacker_.getAttackType() != AttackType::NONE) {
        bsmAccel = accelAttacker_.getValue(trueBsmAccel, currentTime, accelValid);
    }

    // Position attacks (van der Heijden VNC 2017)
    // Per van der Heijden: "position falsification...only crashes consensus controller"
    double bsmPosition = trueBsmPosition;
    if (attackerEnabled_ && positionAttacker_.getAttackType() != AttackType::NONE) {
        bsmPosition = positionAttacker_.getValue(trueBsmPosition, currentTime, positionValid);
    }

    // Record all BSM fields (attacked or not)
    bsmAccelOut_.record(bsmAccel);
    bsmPositionOut_.record(bsmPosition);

    // Simulate radar measurement - uses GROUND TRUTH (not BSM) + sensor noise
    // In real system, radar measures actual vehicle position/speed independently
    double radarSpeed = trueBsmSpeed + radarNoiseDist_(rng_) * 0.5;

    // Record attack status (any of the three attackers)
    bool underAttack = attackerEnabled_ && (
        attacker_.isUnderAttack() ||
        accelAttacker_.isUnderAttack() ||
        positionAttacker_.isUnderAttack()
    );
    attackActiveOut_.record(underAttack ? 1 : 0);

    // Handle DoS/Denial attack - detect missing packets
    if (!bsmValid) {
        EV_WARN << "BSM dropped by denial attack at t=" << currentTime << "\n";
        // Count consecutive drops for DoS detection
        consecutiveDrops_++;
        if (consecutiveDrops_ >= 3) {
            // Trigger attack detection on packet loss
            double confidence = 0.0, anomalyScore = 0.0;
            int votes = 2;  // Consider DoS as detected
            automaton_.transition(true, currentTime, 1.0);
            defenseModeOut_.record(static_cast<int>(automaton_.getMode()));
        }
        return;
    }
    consecutiveDrops_ = 0;  // Reset on valid packet

    // Record BSM and radar values
    bsmSpeedOut_.record(bsmSpeed);
    radarSpeedOut_.record(radarSpeed);

    // Calculate residual for detection
    double residual = std::abs(bsmSpeed - radarSpeed);
    residualOut_.record(residual);

    //=========================================================================
    // Ensemble Detection (with timestamp freshness for replay detection)
    //=========================================================================
    double confidence, anomalyScore;
    int votes;
    bool attackDetected = detector_.check(bsmSpeed, radarSpeed, currentTime,
                                          confidence, anomalyScore, votes,
                                          bsmTimestamp);

    detectorVotesOut_.record(votes);

    //=========================================================================
    // Hybrid Automaton State Transition
    //=========================================================================
    // Local sensor confidence based on radar availability
    double localSensorConfidence = 1.0;  // Assume radar always available in simulation

    automaton_.transition(attackDetected, currentTime, localSensorConfidence);

    DefenseMode mode = automaton_.getMode();
    defenseModeOut_.record(static_cast<int>(mode));

    //=========================================================================
    // Sensor Fusion based on Defense Mode
    //=========================================================================
    double fusedSpeed = automaton_.fuseSensors(bsmSpeed, radarSpeed);
    fusedSpeedOut_.record(fusedSpeed);

    // Log mode transitions
    if (attackDetected && votes >= 2) {
        EV_INFO << "Attack detected at t=" << currentTime
                << " mode=" << automaton_.getModeString()
                << " votes=" << votes
                << " residual=" << residual << "\n";
    }

    // Store for next iteration
    lastBsmSpeed_ = trueBsmSpeed;
    lastBsmDistance_ = pkt->getPositionX();  // Simplified - use X position
    lastBsmAccel_ = pkt->getAcceleration();
    lastRadarSpeed_ = radarSpeed;
}

} // namespace security
} // namespace plexe
