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
        // Attack Injection (for benchmarking/testing)
        //=====================================================================
        bool attackerEnabled = default(false);

        // Attack type: none, constant, offset, random, noise, replay, drift, denial
        string attackType = default("none");

        // Attack magnitude (interpretation depends on attack type):
        //   - constant: the fake value to report
        //   - offset: meters to add to true value
        //   - random: max range for random values
        //   - noise: noise multiplier
        //   - drift: drift rate in m/s
        //   - denial: drop probability (0-1)
        //   - replay: not used (uses fixed 3s delay)
        double attackMagnitude = default(0.0);

        // When attack starts (simulation seconds)
        double attackStartTime = default(10.0);

        // Attack duration (-1 for indefinite)
        double attackDuration = default(-1);
}
