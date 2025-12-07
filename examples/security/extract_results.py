#!/usr/bin/env python3
"""
Extract simulation results for paper Tables 1 and 2.

This script processes OMNeT++ vector files from PrimaryBenchmark and
UndefendedBenchmark simulations to output metrics for the paper.

Table 1 - Attack Detection Performance:
  - Detection latency (time from attack onset to detection)
  - Fusion effectiveness (% reduction in BSM-radar residual)
  - Mitigation (average residual reduction in m/s)

Table 2 - Safety Comparison (Defended vs Undefended):
  - Min TTC (Time-to-Collision)
  - Collisions
  - Min headway during attack

Usage:
    python extract_results.py [results_dir]

If results_dir is not specified, defaults to ./results/
"""

import sys
from pathlib import Path

# Attack configurations matching omnetpp.ini PrimaryBenchmark
# 5 verified attacks from peer-reviewed literature
ATTACKS = [
    ('constant', '0 m/s', 'van der Heijden', 'speed'),
    ('offset', '+150 m/s', 'van der Heijden', 'speed'),
    ('replay', '3s delay', 'experimental', 'speed'),
    ('accel_offset', '-30 m/s^2', 'van der Heijden', 'accel'),
    ('accel_constant', '+6 m/s^2', 'Amoozadeh', 'accel'),
]

# Simulation parameters
ATTACK_START_TIME = 30.0  # seconds
ATTACK_END_TIME = 70.0    # seconds (40s duration)


def parse_vector_file(filepath, extract_safety=False):
    """
    Parse an OMNeT++ .vec file and extract relevant time series data.

    Args:
        filepath: Path to the .vec file
        extract_safety: If True, also extract distance/speed for TTC calculation

    Returns dict with:
        - detection_time: first time attackDetected=1 after attack start
        - speed_errors: dict with 'bsm' and 'fused' error lists (vs ground truth)
        - accel_errors: dict with 'bsm' and 'fused' error lists (vs ground truth)
        - min_ttc: minimum time-to-collision during attack (if extract_safety)
        - min_headway: minimum headway during attack (if extract_safety)
        - collisions: number of collision events (if extract_safety)
    """
    vector_ids = {}

    # First pass: identify vector IDs for node[1] (first follower)
    with open(filepath, 'r') as f:
        for line in f:
            if line.startswith('vector'):
                parts = line.split()
                if len(parts) >= 4:
                    vec_id = parts[1]
                    module = parts[2]
                    name = parts[3]
                    # Track node[1] - the first follower vehicle
                    if 'node[1]' in module:
                        if name == 'bsmSpeed':
                            vector_ids['bsmSpeed'] = vec_id
                        elif name == 'radarSpeed':
                            vector_ids['radarSpeed'] = vec_id
                        elif name == 'fusedSpeed':
                            vector_ids['fusedSpeed'] = vec_id
                        elif name == 'trueSpeed':
                            vector_ids['trueSpeed'] = vec_id
                        elif name == 'bsmAccel':
                            vector_ids['bsmAccel'] = vec_id
                        elif name == 'trueAccel':
                            vector_ids['trueAccel'] = vec_id
                        elif name == 'fusedAccel':
                            vector_ids['fusedAccel'] = vec_id
                        elif 'attackDetected' in name:
                            vector_ids['attackDetected'] = vec_id
                        elif name == 'headway':
                            vector_ids['headway'] = vec_id
                    # Distance and relativeSpeed from appl module
                    if 'node[1].appl' in module:
                        if name == 'distance':
                            vector_ids['distance'] = vec_id
                        elif name == 'relativeSpeed':
                            vector_ids['relativeSpeed'] = vec_id

    # Second pass: extract data
    data_series = {key: {} for key in ['bsmSpeed', 'radarSpeed', 'fusedSpeed', 'trueSpeed',
                                        'bsmAccel', 'trueAccel', 'fusedAccel']}
    detection_time = None

    # Safety data
    distance_data = {}
    rel_speed_data = {}
    headway_data = {}

    with open(filepath, 'r') as f:
        for line in f:
            parts = line.split('\t')
            if len(parts) >= 4:
                vec_id = parts[0]
                try:
                    time = float(parts[2])
                    value = float(parts[3])
                except (ValueError, IndexError):
                    continue

                # Track detection time
                if vec_id == vector_ids.get('attackDetected'):
                    if value == 1 and detection_time is None and time >= ATTACK_START_TIME:
                        detection_time = time

                # Collect data during attack period
                if ATTACK_START_TIME <= time <= ATTACK_END_TIME:
                    for key in data_series:
                        if vec_id == vector_ids.get(key):
                            data_series[key][time] = value

                    # Safety metrics
                    if extract_safety:
                        if vec_id == vector_ids.get('distance'):
                            distance_data[time] = value
                        elif vec_id == vector_ids.get('relativeSpeed'):
                            rel_speed_data[time] = value
                        elif vec_id == vector_ids.get('headway'):
                            headway_data[time] = value

    # Calculate errors vs ground truth at common timestamps
    # Speed errors: |bsm - true| and |fused - true|
    speed_common = set(data_series['bsmSpeed'].keys()) & set(data_series['trueSpeed'].keys())
    speed_errors = {'bsm': [], 'fused': []}
    for t in speed_common:
        bsm_err = abs(data_series['bsmSpeed'][t] - data_series['trueSpeed'][t])
        speed_errors['bsm'].append(bsm_err)
        if t in data_series['fusedSpeed']:
            fused_err = abs(data_series['fusedSpeed'][t] - data_series['trueSpeed'][t])
            speed_errors['fused'].append(fused_err)

    # Accel errors: |bsm - true| and |fused - true|
    accel_common = set(data_series['bsmAccel'].keys()) & set(data_series['trueAccel'].keys())
    accel_errors = {'bsm': [], 'fused': []}
    for t in accel_common:
        bsm_err = abs(data_series['bsmAccel'][t] - data_series['trueAccel'][t])
        accel_errors['bsm'].append(bsm_err)
        if t in data_series['fusedAccel']:
            fused_err = abs(data_series['fusedAccel'][t] - data_series['trueAccel'][t])
            accel_errors['fused'].append(fused_err)

    result = {
        'detection_time': detection_time,
        'speed_errors': speed_errors,
        'accel_errors': accel_errors,
    }

    # Calculate safety metrics
    if extract_safety:
        # Compute TTC at each timestep where we're closing
        ttc_values = []
        common_safety_times = set(distance_data.keys()) & set(rel_speed_data.keys())
        for t in common_safety_times:
            dist = distance_data[t]
            rel_speed = rel_speed_data[t]
            # TTC only meaningful when closing (positive relative speed = closing)
            if rel_speed > 0.1 and dist > 0:
                ttc = dist / rel_speed
                ttc_values.append(ttc)

        result['min_ttc'] = min(ttc_values) if ttc_values else float('inf')
        result['min_headway'] = min(headway_data.values()) if headway_data else float('inf')
        result['collisions'] = 1 if (result['min_headway'] < 0.1 or result['min_ttc'] < 0.1) else 0

    return result


def compute_metrics(data, attack_field='speed'):
    """
    Compute table metrics from parsed data using unified ground-truth-based metric.

    The unified metric measures: |fused - truth| vs |bsm - truth|
    This works for both speed and acceleration attacks.

    Args:
        data: parsed vector file data
        attack_field: 'speed' or 'accel' - which field the attack targets

    Returns:
        detection_latency: time from attack start to detection (seconds)
        mitigation_pct: % reduction in error vs ground truth
        avg_attack_error: average |bsm - truth| during attack (shows attack magnitude)
    """
    # Detection latency
    if data['detection_time'] is not None:
        detection_latency = data['detection_time'] - ATTACK_START_TIME
    else:
        detection_latency = None

    # Select appropriate error data based on attack field
    if attack_field == 'accel':
        errors = data['accel_errors']
    else:
        errors = data['speed_errors']

    # Unified mitigation metric: reduction in error vs ground truth
    if errors['bsm'] and errors['fused']:
        avg_bsm_err = sum(errors['bsm']) / len(errors['bsm'])
        avg_fused_err = sum(errors['fused']) / len(errors['fused'])

        # Only compute metrics if attack has meaningful impact (>0.5 error)
        if avg_bsm_err > 0.5:
            mitigation_pct = (avg_bsm_err - avg_fused_err) / avg_bsm_err * 100
            avg_attack_error = avg_bsm_err
        else:
            mitigation_pct = None
            avg_attack_error = avg_bsm_err
    else:
        mitigation_pct = None
        avg_attack_error = None

    return detection_latency, mitigation_pct, avg_attack_error


def print_table1(results_dir):
    """Print Table 1: Attack Detection Performance with unified mitigation metric"""
    print()
    print("TABLE 1: Attack Detection Performance (PrimaryBenchmark)")
    print("=" * 90)
    print()
    print(f"{'Attack Type':<20} {'Parameter':<15} {'Detection':<12} {'Mitigation':<12} {'Attack Mag':<15}")
    print("-" * 90)

    for attack_name, param, source, attack_field in ATTACKS:
        vec_file = results_dir / f'PrimaryBenchmark_"{attack_name}"_0.vec'

        if not vec_file.exists():
            print(f"{attack_name:<20} {'MISSING':<15}")
            continue

        data = parse_vector_file(vec_file)
        detection, mitigation_pct, attack_mag = compute_metrics(data, attack_field)

        # Format detection time
        if detection is None:
            det_str = 'N/A'
        elif detection < 1.0:
            det_str = f'{detection*1000:.0f} ms'
        else:
            det_str = f'{detection:.2f} s'

        # Format mitigation percentage and attack magnitude
        if mitigation_pct is not None:
            mit_str = f'{mitigation_pct:.1f}%'
        else:
            mit_str = 'N/A'

        # Show attack magnitude (error vs ground truth)
        if attack_mag is not None:
            if attack_field == 'accel':
                mag_str = f'{attack_mag:.1f} m/s²'
            else:
                mag_str = f'{attack_mag:.1f} m/s'
        else:
            mag_str = 'N/A'

        print(f"{attack_name:<20} {param:<15} {det_str:<12} {mit_str:<12} {mag_str:<15}")

    print("-" * 90)
    print()
    print("Notes:")
    print("  - Detection: time from attack onset (t=30s) to first detection")
    print("  - Mitigation: % reduction in |output - truth| error (unified metric)")
    print("  - Attack Mag: average |BSM - truth| during attack period")
    print("  - Braking event at t=35s tests replay attack during dynamic conditions")


def print_table2(results_dir):
    """Print Table 2: Safety Comparison (Defended vs Undefended)"""
    print()
    print()
    print("TABLE 2: Safety Comparison - Defended vs Undefended CACC")
    print("=" * 80)
    print()
    print(f"{'Attack Type':<20} {'TTC (Def)':<12} {'TTC (Undef)':<12} {'Gap (Def)':<12} {'Gap (Undef)':<12}")
    print("-" * 80)

    total_collisions_def = 0
    total_collisions_undef = 0

    for attack_name, param, source, attack_field in ATTACKS:
        # Defended results
        def_file = results_dir / f'PrimaryBenchmark_"{attack_name}"_0.vec'
        # Undefended results
        undef_file = results_dir / f'UndefendedBenchmark_"{attack_name}"_0.vec'

        def_data = None
        undef_data = None

        if def_file.exists():
            def_data = parse_vector_file(def_file, extract_safety=True)
            total_collisions_def += def_data.get('collisions', 0)

        if undef_file.exists():
            undef_data = parse_vector_file(undef_file, extract_safety=True)
            total_collisions_undef += undef_data.get('collisions', 0)

        # Format TTC
        def format_ttc(ttc):
            if ttc is None or ttc == float('inf'):
                return '>10s'
            elif ttc > 10:
                return '>10s'
            else:
                return f'{ttc:.2f}s'

        def format_gap(gap):
            if gap is None or gap == float('inf'):
                return '---'
            else:
                return f'{gap:.2f}m'

        if def_data:
            ttc_def = format_ttc(def_data.get('min_ttc'))
            gap_def = format_gap(def_data.get('min_headway'))
        else:
            ttc_def = 'MISSING'
            gap_def = 'MISSING'

        if undef_data:
            ttc_undef = format_ttc(undef_data.get('min_ttc'))
            gap_undef = format_gap(undef_data.get('min_headway'))
        else:
            ttc_undef = 'MISSING'
            gap_undef = 'MISSING'

        print(f"{attack_name:<20} {ttc_def:<12} {ttc_undef:<12} {gap_def:<12} {gap_undef:<12}")

    print("-" * 80)
    print()
    print(f"Total Collisions:  Defended = {total_collisions_def},  Undefended = {total_collisions_undef}")
    print()
    print("Notes:")
    print("  - TTC: Time-to-Collision (>10s means safe, no closing)")
    print("  - Gap: minimum inter-vehicle headway during attack period")
    print("  - Run 'UndefendedBenchmark' config if undefended results are missing")


def main():
    # Determine results directory
    if len(sys.argv) > 1:
        results_dir = Path(sys.argv[1])
    else:
        results_dir = Path(__file__).parent / 'results'

    if not results_dir.exists():
        print(f"Error: Results directory not found: {results_dir}")
        print("Run the simulation first: ./run -c PrimaryBenchmark")
        sys.exit(1)

    print()
    print("CACC Security Simulation Results Extractor")
    print("=" * 50)
    print(f"Results directory: {results_dir}")

    # Print both tables
    print_table1(results_dir)
    print_table2(results_dir)

    print()


if __name__ == '__main__':
    main()
