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
    : defenseEnabled_(true),
      attackerEnabled_(false),
      radarNoise_(0.5),
      rng_(std::random_device{}()),
      radarNoiseDist_(0.0, 0.5),
      // Ego vehicle state
      egoSpeed_(0),
      egoAccel_(0),
      egoPositionX_(0),
      egoPositionY_(0),
      // BSM state (potentially attacked)
      lastBsmSpeed_(0),
      lastBsmDistance_(0),
      lastBsmAccel_(0),
      // Radar measurements
      lastRadarSpeed_(0),
      lastRadarDistance_(0),
      lastRadarRelativeSpeed_(0),
      prevRadarDistance_(0),
      prevMeasurementTime_(0),
      // DoS detection
      consecutiveDrops_(0),
      // Defense thresholds
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
    headwayOut_.setName("headway");
    activeControllerOut_.setName("activeController");
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

        // Read defense enable parameter
        defenseEnabled_ = par("defenseEnabled").boolValue();

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
                //=============================================================
                // SPEED FIELD ATTACKS
                //=============================================================
                case AttackType::CONSTANT:
                    // van der Heijden VNC 2017: constant fake speed value
                    attacker_.setFakeValue(attackMagnitude_);
                    break;
                case AttackType::OFFSET:
                    // van der Heijden VNC 2017: speed offset attack (50, 100, 150 m/s)
                    attacker_.setOffsetValue(attackMagnitude_);
                    break;
                case AttackType::DRIFT:
                    // Amoozadeh IEEE CommMag 2015: gradual speed drift (m/s per second)
                    attacker_.setDriftRate(attackMagnitude_);
                    break;
                case AttackType::REPLAY:
                    // SAE J2735, ETSI ITS-G5: replay old BSM data (delay in seconds)
                    attacker_.setReplayDelay(attackMagnitude_);
                    break;
                case AttackType::NOISE:
                    // REPLACE taxonomy: amplified measurement noise (multiplier)
                    attacker_.setNoiseMultiplier(attackMagnitude_);
                    break;
                //=============================================================
                // ACCELERATION FIELD ATTACKS
                //=============================================================
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
                //=============================================================
                // POSITION FIELD ATTACKS
                //=============================================================
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
    // Speed field attacks
    if (type == "constant") return AttackType::CONSTANT;       // van der Heijden VNC 2017
    if (type == "offset") return AttackType::OFFSET;           // van der Heijden VNC 2017
    if (type == "drift") return AttackType::DRIFT;             // Amoozadeh IEEE CommMag 2015
    if (type == "replay") return AttackType::REPLAY;           // SAE J2735, ETSI ITS-G5
    if (type == "noise") return AttackType::NOISE;             // REPLACE taxonomy
    // Acceleration field attacks
    if (type == "accel_offset") return AttackType::ACCEL_OFFSET;     // van der Heijden VNC 2017
    if (type == "accel_constant") return AttackType::ACCEL_CONSTANT; // Amoozadeh IEEE CommMag 2015
    // Position field attacks
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

//=============================================================================
// Radar Simulation Methods
//
// Real automotive radar (e.g., Continental ARS4-A) measures:
// 1. Range: distance to target via time-of-flight (σ ≈ 0.1-0.5m)
// 2. Range-rate: relative velocity via Doppler shift (σ ≈ 0.1-0.3 m/s)
// 3. Azimuth: bearing angle (not used here - assumes same lane)
//
// We derive front vehicle absolute speed from:
//   frontSpeed = egoSpeed - rangeRate
// where rangeRate > 0 means closing (getting closer)
//
// Reference: van der Heijden VNC 2017 uses σ = 0.5 m/s for sensor noise
//=============================================================================

double SecureCACCProtocol::getRadarRange(double frontPosX, double frontPosY)
{
    // Calculate Euclidean distance to front vehicle
    // In a platoon, vehicles are typically in same lane (Y ≈ constant)
    double dx = frontPosX - egoPositionX_;
    double dy = frontPosY - egoPositionY_;
    double trueRange = std::sqrt(dx * dx + dy * dy);

    // Add Gaussian noise (typical radar σ = 0.1-0.5m for range)
    double rangeNoise = radarNoiseDist_(rng_) * 0.2;  // σ = 0.1m for range
    double measuredRange = trueRange + rangeNoise;

    return std::max(0.0, measuredRange);
}

double SecureCACCProtocol::getRadarRangeRate(double frontSpeed)
{
    // Range-rate = rate of change of distance = ego_speed - front_speed
    // Positive range-rate = closing (gap decreasing)
    // Negative range-rate = separating (gap increasing)
    //
    // Real radar measures this directly via Doppler shift
    double trueRangeRate = egoSpeed_ - frontSpeed;

    // Add Gaussian noise (typical radar σ = 0.1-0.3 m/s for range-rate)
    double rangeRateNoise = radarNoiseDist_(rng_) * 0.6;  // σ = 0.3 m/s
    double measuredRangeRate = trueRangeRate + rangeRateNoise;

    return measuredRangeRate;
}

double SecureCACCProtocol::getRadarDerivedSpeed(double rangeRate)
{
    // Derive front vehicle absolute speed from ego speed and range-rate
    // frontSpeed = egoSpeed - rangeRate
    //
    // This is how a real system would estimate front vehicle speed
    // without direct communication (radar-only mode)
    double derivedSpeed = egoSpeed_ - rangeRate;

    return std::max(0.0, derivedSpeed);
}

double SecureCACCProtocol::getRadarDistance()
{
    // Legacy method - returns last computed radar range
    return lastRadarDistance_;
}

double SecureCACCProtocol::getRadarSpeed()
{
    // Legacy method - returns last computed radar-derived speed
    return lastRadarSpeed_;
}

void SecureCACCProtocol::messageReceived(PlatooningBeacon* pkt, BaseFrame1609_4* frame)
{
    // Call parent implementation
    SimplePlatooningBeaconing::messageReceived(pkt, frame);

    double currentTime = simTime().dbl();

    //=========================================================================
    // Get ego vehicle state from SUMO (ground truth for own vehicle)
    //=========================================================================
    VEHICLE_DATA egoData;
    plexeTraciVehicle->getVehicleData(&egoData);
    egoSpeed_ = egoData.speed;
    egoAccel_ = egoData.acceleration;
    egoPositionX_ = egoData.positionX;
    egoPositionY_ = egoData.positionY;

    //=========================================================================
    // Get front vehicle BSM data (ground truth from SUMO, potentially attacked)
    //=========================================================================
    double trueBsmSpeed = pkt->getSpeed();
    double trueBsmAccel = pkt->getAcceleration();
    double trueBsmPositionX = pkt->getPositionX();
    double trueBsmPositionY = pkt->getPositionY();
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
    double bsmPosition = trueBsmPositionX;
    if (attackerEnabled_ && positionAttacker_.getAttackType() != AttackType::NONE) {
        bsmPosition = positionAttacker_.getValue(trueBsmPositionX, currentTime, positionValid);
    }

    // Record all BSM fields (attacked or not)
    bsmAccelOut_.record(bsmAccel);
    bsmPositionOut_.record(bsmPosition);

    //=========================================================================
    // Radar Simulation - Independent local sensor measurement
    //
    // Real automotive radar measures:
    // 1. Range (distance) via time-of-flight
    // 2. Range-rate (relative velocity) via Doppler shift
    // 3. We derive front vehicle absolute speed from: frontSpeed = egoSpeed - rangeRate
    //
    // Uses GROUND TRUTH positions/speeds from SUMO + realistic sensor noise
    //=========================================================================

    // Measure range to front vehicle (ground truth + noise)
    lastRadarDistance_ = getRadarRange(trueBsmPositionX, trueBsmPositionY);

    // Measure range-rate (relative velocity via Doppler, ground truth + noise)
    double rangeRate = getRadarRangeRate(trueBsmSpeed);
    lastRadarRelativeSpeed_ = rangeRate;

    // Derive front vehicle absolute speed from ego speed and range-rate
    // This is how a radar-only system would estimate front vehicle speed
    double radarSpeed = getRadarDerivedSpeed(rangeRate);
    lastRadarSpeed_ = radarSpeed;

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
    // Local acceleration measurement (from own vehicle IMU/accelerometer)
    //
    // For detecting acceleration attacks on the FRONT vehicle's BSM, we need
    // to estimate what the front vehicle's acceleration should be.
    //
    // Method: Use the derivative of radar-derived speed (numerical differentiation)
    // or compare BSM accel against expected accel from CACC dynamics.
    //
    // Here we use ground truth + noise as a simplified model of what an
    // observer-based estimator would compute from radar measurements.
    //=========================================================================
    double localAccel = trueBsmAccel + radarNoiseDist_(rng_) * 0.3;  // σ = 0.15 m/s² for accel

    //=========================================================================
    // Ensemble Detection (speed + acceleration fields)
    // Per van der Heijden VNC 2017: accel attacks are "most dangerous"
    //=========================================================================
    double confidence, anomalyScore;
    int votes = 0;
    bool attackDetected = false;
    double fusedSpeed = bsmSpeed;  // Default: trust BSM (no defense)

    if (defenseEnabled_) {
        // Run detection only if defense is enabled
        attackDetected = detector_.check(bsmSpeed, radarSpeed, currentTime,
                                              confidence, anomalyScore, votes,
                                              bsmTimestamp,
                                              bsmAccel, localAccel);

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
        fusedSpeed = automaton_.fuseSensors(bsmSpeed, radarSpeed);
        fusedSpeedOut_.record(fusedSpeed);

        // Log mode transitions
        if (attackDetected && votes >= 2) {
            EV_INFO << "Attack detected at t=" << currentTime
                    << " mode=" << automaton_.getModeString()
                    << " votes=" << votes
                    << " residual=" << residual << "\n";
        }

        //=========================================================================
        // Headway Adjustment (Graceful Degradation per Ploeg 2015)
        //
        // When defense mode changes, adjust controller headway to maintain
        // string stability:
        //   NORMAL: h = 0.5s (full CACC with V2V feedforward)
        //   DETECTED: h = 1.24s (degraded CACC with estimated acceleration)
        //   ACTIVE: h = 3.16s (ACC fallback, radar-only)
        //   DEGRADED: h = 3.16s (conservative ACC with safety margins)
        //=========================================================================
        if (automaton_.hasHeadwayChanged()) {
            applyHeadwayAdjustment();
            automaton_.clearHeadwayChanged();
        }

        // Record current headway and controller state
        headwayOut_.record(automaton_.getTargetHeadway());
        activeControllerOut_.record(automaton_.shouldUseACC() ? ACC : CACC);
    } else {
        // Defense disabled: record baseline metrics
        detectorVotesOut_.record(0);
        defenseModeOut_.record(0);  // Always NORMAL
        fusedSpeedOut_.record(bsmSpeed);  // Trust BSM directly (vulnerable)
        headwayOut_.record(0.5);  // Fixed CACC headway
        activeControllerOut_.record(CACC);
    }

    // Store for next iteration
    lastBsmSpeed_ = trueBsmSpeed;
    lastBsmDistance_ = pkt->getPositionX();  // Simplified - use X position
    lastBsmAccel_ = pkt->getAcceleration();
    lastRadarSpeed_ = radarSpeed;
}

//=============================================================================
// applyHeadwayAdjustment - Apply graceful degradation headway changes
//
// Per Ploeg et al. IEEE T-ITS 2015 "Graceful degradation of CACC":
//   - CACC with feedforward: h >= 0.25s (we use 0.5s)
//   - Degraded CACC (Kalman-estimated accel): h >= 1.23s (we use 1.24s)
//   - ACC (radar-only, no feedforward): h >= 3.16s
//
// The controller type determines string stability requirements:
//   - CACC uses predecessor acceleration from V2V (potentially attacked)
//   - ACC uses only radar-derived relative velocity (trusted sensor)
//=============================================================================
void SecureCACCProtocol::applyHeadwayAdjustment()
{
    double targetHeadway = automaton_.getTargetHeadway();
    DefenseMode mode = automaton_.getMode();

    EV_INFO << "Applying headway adjustment: h=" << targetHeadway
            << "s for mode " << automaton_.getModeString() << "\n";

    // For DEFENSE_ACTIVE and DEGRADED modes, we should ideally switch to ACC
    // However, this requires changing the active controller which affects
    // the entire control architecture. For now, we adjust headway which
    // provides the primary safety benefit (increased following distance).
    //
    // The Ploeg controller supports runtime headway changes via setPloegCACCParameters

    if (automaton_.shouldUseACC()) {
        // In DEFENSE_ACTIVE or DEGRADED mode: use ACC-equivalent headway
        // This effectively disables feedforward benefits but ensures
        // string stability with radar-only measurements
        //
        // We set the Ploeg CACC headway to ACC-stable value (3.16s)
        // The sensor fusion already uses radar-only in these modes
        plexeTraciVehicle->setPloegCACCParameters(-1, -1, targetHeadway);

        // Also set ACC headway for consistency
        plexeTraciVehicle->setACCHeadwayTime(targetHeadway);

        EV_INFO << "Defense mode: Set ACC-equivalent headway h=" << targetHeadway << "s\n";
    } else if (mode == DefenseMode::ATTACK_DETECTED) {
        // Degraded CACC mode: intermediate headway
        // Still using CACC controller but with larger safety margin
        plexeTraciVehicle->setPloegCACCParameters(-1, -1, targetHeadway);

        EV_INFO << "Degraded CACC mode: Set headway h=" << targetHeadway << "s\n";
    } else {
        // NORMAL mode: restore full CACC headway
        plexeTraciVehicle->setPloegCACCParameters(-1, -1, targetHeadway);

        EV_INFO << "Normal mode: Restored CACC headway h=" << targetHeadway << "s\n";
    }
}

} // namespace security
} // namespace plexe
