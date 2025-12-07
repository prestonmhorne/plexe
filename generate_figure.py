#!/usr/bin/env python3
"""
Generate figures comparing defended vs undefended CACC under attack.

Creates a figure showing headway over time for the position_shift attack,
which is the most visually interesting case (defended increases gap to 3.16m).

Usage:
    python generate_figure.py [results_dir]

Output: defense_comparison.pdf in the current directory
"""

import sys
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for PDF generation

# Simulation parameters
ATTACK_START_TIME = 30.0
ATTACK_END_TIME = 70.0


def parse_timeseries(filepath, vector_name, module_filter='node[1]'):
    """Extract a time series from an OMNeT++ .vec file."""
    vector_id = None

    # First pass: find vector ID
    with open(filepath, 'r') as f:
        for line in f:
            if line.startswith('vector'):
                parts = line.split()
                if len(parts) >= 4:
                    vid = parts[1]
                    module = parts[2]
                    name = parts[3]
                    if module_filter in module and name == vector_name:
                        vector_id = vid
                        break

    if vector_id is None:
        return [], []

    # Second pass: extract data
    times = []
    values = []

    with open(filepath, 'r') as f:
        for line in f:
            parts = line.split('\t')
            if len(parts) >= 4 and parts[0] == vector_id:
                try:
                    t = float(parts[2])
                    v = float(parts[3])
                    times.append(t)
                    values.append(v)
                except (ValueError, IndexError):
                    continue

    return times, values


def main():
    # Determine results directory
    if len(sys.argv) > 1:
        results_dir = Path(sys.argv[1])
    else:
        results_dir = Path(__file__).parent / 'results'

    if not results_dir.exists():
        print(f"Error: Results directory not found: {results_dir}")
        sys.exit(1)

    # Use offset attack - shows clear detection timing at attack onset
    attack = 'offset'

    def_file = results_dir / f'PrimaryBenchmark_"{attack}"_0.vec'
    undef_file = results_dir / f'UndefendedBenchmark_"{attack}"_0.vec'

    if not def_file.exists():
        print(f"Error: Missing defended results: {def_file}")
        sys.exit(1)

    # Create figure with 2 subplots
    fig, axes = plt.subplots(2, 1, figsize=(8, 6), sharex=True)

    # Plot 1: Headway comparison
    ax1 = axes[0]

    # Defended headway
    t_def, h_def = parse_timeseries(def_file, 'headway', 'node[1].prot')
    if t_def:
        ax1.plot(t_def, h_def, 'b-', linewidth=1.5, label='Defended (Ensemble + Graceful Degradation)')

    # Undefended headway
    if undef_file.exists():
        t_undef, h_undef = parse_timeseries(undef_file, 'headway', 'node[1].prot')
        if t_undef:
            ax1.plot(t_undef, h_undef, 'r--', linewidth=1.5, label='Undefended (Raw CACC)')

    # Mark attack period
    ax1.axvspan(ATTACK_START_TIME, ATTACK_END_TIME, alpha=0.15, color='red', label='Attack Period')
    ax1.axvline(ATTACK_START_TIME, color='red', linestyle=':', alpha=0.5)
    ax1.axvline(ATTACK_END_TIME, color='red', linestyle=':', alpha=0.5)

    ax1.set_ylabel('Headway (s)')
    ax1.set_title('Offset Attack (+150 m/s): Defended vs Undefended')
    ax1.legend(loc='upper right', fontsize=9)
    ax1.grid(True, alpha=0.3)
    ax1.set_ylim(0, 5)

    # Plot 2: BSM Speed Residual (shows attack impact)
    ax2 = axes[1]

    # Get BSM and radar speed to compute residual
    t_bsm, v_bsm = parse_timeseries(def_file, 'bsmSpeed', 'node[1].prot')
    t_radar, v_radar = parse_timeseries(def_file, 'radarSpeed', 'node[1].prot')

    if t_bsm and t_radar:
        # Compute residual at common times
        bsm_dict = {t: v for t, v in zip(t_bsm, v_bsm)}
        radar_dict = {t: v for t, v in zip(t_radar, v_radar)}
        common = sorted(set(bsm_dict.keys()) & set(radar_dict.keys()))

        residual_t = []
        residual_v = []
        for t in common:
            residual_t.append(t)
            residual_v.append(abs(bsm_dict[t] - radar_dict[t]))

        ax2.plot(residual_t, residual_v, 'g-', linewidth=1, label='|BSM - Radar| Residual')

    ax2.axvspan(ATTACK_START_TIME, ATTACK_END_TIME, alpha=0.15, color='red')
    ax2.axvline(ATTACK_START_TIME, color='red', linestyle=':', alpha=0.5)
    ax2.axvline(ATTACK_END_TIME, color='red', linestyle=':', alpha=0.5)

    ax2.set_xlabel('Time (s)')
    ax2.set_ylabel('Speed Residual (m/s)')
    ax2.legend(loc='upper right', fontsize=9)
    ax2.grid(True, alpha=0.3)
    ax2.set_xlim(0, 120)

    plt.tight_layout()

    # Save figure
    output_path = Path(__file__).parent / 'defense_comparison.pdf'
    plt.savefig(output_path, format='pdf', bbox_inches='tight', dpi=300)
    print(f"Figure saved to: {output_path}")

    # Also save PNG for quick preview
    png_path = Path(__file__).parent / 'defense_comparison.png'
    plt.savefig(png_path, format='png', bbox_inches='tight', dpi=150)
    print(f"Preview saved to: {png_path}")


if __name__ == '__main__':
    main()
