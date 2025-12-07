//
// SecureCACCProtocol.ned - NED definition for Secure CACC Protocol
//
// CS 6376 Final Project - Resilient V2V ACC Defense
// Vanderbilt University - Preston Horne
//
// Extends SimplePlatooningBeaconing with hybrid automaton defense
// for detecting and mitigating FDI attacks on V2V BSM messages.
//

package org.car2x.plexe.security;

import org.car2x.plexe.protocols.SimplePlatooningBeaconing;

//
// SecureCACCProtocol extends SimplePlatooningBeaconing with:
//   - FDI attack injection capability (for testing)
//   - Hybrid automaton defense (4 states)
//   - Ensemble detection (threshold, Kalman, CUSUM)
//   - Mode-dependent sensor fusion
//
simple SecureCACCProtocol extends SimplePlatooningBeaconing
{
    parameters:
        @class(plexe::security::SecureCACCProtocol);
        @display("i=block/control");

        //=====================================================================
        // Defense Thresholds
        //=====================================================================
        double positionThreshold = default(5.0);  // Position anomaly threshold (meters)
        double speedThreshold = default(3.0);     // Speed anomaly threshold (m/s)
        double accelThreshold = default(4.0);     // Acceleration threshold (m/s^2)
        double kalmanThreshold = default(7.815);  // Kalman detector chi-square threshold
        double cusumThreshold = default(5.0);     // CUSUM decision boundary
        double cusumDrift = default(2.0);         // CUSUM drift allowance δ (Paper Eq. 13)

        //=====================================================================
        // Sensor Fusion
        //=====================================================================
        // Hedging parameter: 0 = trust BSM, 1 = trust radar
        double hedgingAlpha = default(0.5);

        //=====================================================================
        // Simulated Radar Parameters
        //=====================================================================
        double radarNoise = default(0.5);  // Radar noise std dev σ=0.5 m/s (Van der Heijden 2017)

        //=====================================================================
        // Defense Enable/Disable (for benchmarking comparison)
        //=====================================================================
        bool defenseEnabled = default(true);  // Enable hybrid automaton defense

        //=====================================================================
        // Attack Injection (for benchmarking/testing)
        // All 8 FDI attacks from peer-reviewed CACC security literature
        //=====================================================================
        bool attackerEnabled = default(false);

        // Attack type - 8 standard FDI attacks:
        //   Speed field:  constant, offset, drift, replay, noise
        //   Accel field:  accel_offset, accel_constant
        //   Position:     position_shift
        string attackType = default("none");

        // Attack magnitude (interpretation depends on attack type):
        //   - constant:       fake speed value (m/s) [van der Heijden VNC 2017]
        //   - offset:         speed offset (m/s) [van der Heijden: 50, 100, 150]
        //   - drift:          drift rate (m/s per second) [Amoozadeh]
        //   - replay:         replay delay (seconds) [SAE J2735]
        //   - noise:          noise multiplier [REPLACE taxonomy]
        //   - accel_offset:   accel offset (m/s^2) [van der Heijden: -30 to +30]
        //   - accel_constant: fake accel value (m/s^2) [Amoozadeh: 6]
        //   - position_shift: position shift rate (m/s) [van der Heijden: 3-11]
        double attackMagnitude = default(0.0);

        // When attack starts (simulation seconds)
        double attackStartTime = default(10.0);

        // Attack duration (-1 for indefinite)
        double attackDuration = default(-1);
}
