#!/usr/bin/env python3
"""
Build and run the CACC security benchmark simulations.

This script:
1. Rebuilds the Plexe simulation with latest code changes
2. Runs the PrimaryBenchmark configuration for all 5 verified attack types
3. Extracts and displays results

Usage:
    python run_benchmark.py [--skip-build] [--attacks ATTACK1,ATTACK2,...]

Options:
    --skip-build    Skip the build step (use existing binary)
    --attacks       Comma-separated list of attacks to run (default: all)
"""

import subprocess
import sys
import os
from pathlib import Path

# Attack configurations - 5 verified attacks from peer-reviewed literature
ALL_ATTACKS = [
    'constant',
    'offset',
    'replay',
    'accel_offset',
    'accel_constant',
]

def run_command(cmd, cwd=None, description=None):
    """Run a shell command and return success status."""
    if description:
        print(f"\n{'='*60}")
        print(f" {description}")
        print(f"{'='*60}")

    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=cwd)
    return result.returncode == 0

def build_plexe(plexe_dir):
    """Build the Plexe simulation."""
    print("\n" + "="*60)
    print(" Building Plexe...")
    print("="*60)

    # Clean and rebuild
    if not run_command("make -j4", cwd=plexe_dir):
        print("ERROR: Build failed!")
        return False

    print("Build successful!")
    return True

def run_simulation(security_dir, attack_type):
    """Run simulation for a specific attack type."""
    print(f"\n--- Running {attack_type} attack simulation ---")

    # Run the simulation
    cmd = f'./run -u Cmdenv -c PrimaryBenchmark -r 0 --repeat=1 --cmdenv-express-mode=true'

    # Set attack type via command line
    cmd += f' --*.node[1..7].prot.attackType=\\"{attack_type}\\"'

    # Set corresponding magnitude
    magnitudes = {
        'constant': 0.0,
        'offset': 150.0,
        'replay': 3.0,
        'accel_offset': -30.0,
        'accel_constant': 6.0,
        'position_shift': 30.0,  # Boddupalli REPLACE: +30m offset
    }
    cmd += f' --*.node[1..7].prot.attackMagnitude={magnitudes[attack_type]}'

    result = subprocess.run(cmd, shell=True, cwd=security_dir, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"WARNING: Simulation returned non-zero exit code")
        if result.stderr:
            print(f"stderr: {result.stderr[:500]}")

    return result.returncode == 0

def run_all_simulations(security_dir, attacks):
    """Run PrimaryBenchmark for specified attacks."""
    print("\n" + "="*60)
    print(" Running Simulations")
    print("="*60)

    # Use opp_runall for parallel execution if available
    cmd = './run -u Cmdenv -c PrimaryBenchmark --cmdenv-express-mode=true'

    if not run_command(cmd, cwd=security_dir, description="Running PrimaryBenchmark (all attacks)"):
        print("WARNING: Some simulations may have failed")
        return False

    return True

def extract_results(security_dir):
    """Extract and display results."""
    print("\n" + "="*60)
    print(" Extracting Results")
    print("="*60)

    result = subprocess.run(
        [sys.executable, 'extract_results.py'],
        cwd=security_dir,
        capture_output=True,
        text=True
    )

    print(result.stdout)
    if result.stderr:
        print(result.stderr)

    return result.returncode == 0

def main():
    # Parse arguments
    skip_build = '--skip-build' in sys.argv

    attacks = ALL_ATTACKS
    for arg in sys.argv[1:]:
        if arg.startswith('--attacks='):
            attacks = arg.split('=')[1].split(',')

    # Determine paths
    script_dir = Path(__file__).parent.resolve()
    security_dir = script_dir
    plexe_dir = script_dir.parent.parent  # plexe/examples/security -> plexe

    print("CACC Security Benchmark Runner")
    print("="*60)
    print(f"Plexe directory: {plexe_dir}")
    print(f"Security example: {security_dir}")
    print(f"Attacks to run: {', '.join(attacks)}")
    print(f"Skip build: {skip_build}")

    # Build if needed
    if not skip_build:
        if not build_plexe(plexe_dir):
            sys.exit(1)

    # Run simulations
    if not run_all_simulations(security_dir, attacks):
        print("WARNING: Some simulations may have issues")

    # Extract results
    extract_results(security_dir)

    print("\n" + "="*60)
    print(" Benchmark Complete!")
    print("="*60)

if __name__ == '__main__':
    main()
