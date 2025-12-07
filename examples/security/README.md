# CACC Security Benchmark

This example demonstrates a sensor fusion defense mechanism for Cooperative Adaptive Cruise Control (CACC) against false data injection (FDI) attacks.

## Project Structure

- **`src/plexe/security/`** - C++ implementation of the defense mechanism:
  - `SecureCACCProtocol.cc/.h/.ned` - Main CACC protocol with sensor fusion
  - `HybridAutomatonDefense.h` - 3-state defense automaton with 2-of-4 voting
  - `FDIAttackInjector.h` - Attack injection library (6 attack types)

- **`examples/security/`** - Simulation configuration and benchmark scripts (this folder)

## Prerequisites

1. **OMNeT++**: https://omnetpp.org/
2. **SUMO**: https://sumo.dlr.de/
3. **Veins**: https://veins.car2x.org/
4. **Plexe**: Build from this repository

Tested with OMNeT++ 6.2.0, Veins 5.3.1, SUMO 1.20.0

### Building Plexe

```bash
# From the repository root
./configure
make -j4
```

## Running the Benchmark

```bash
cd examples/security

# Option 1: Run everything (build + simulate + extract results)
python3 run_benchmark.py

# Option 2: Skip build if already compiled
python3 run_benchmark.py --skip-build
```

## Extracting Results

After simulations complete, results are saved to `./results/`. To view the summary tables:

```bash
python3 extract_results.py
```

This outputs:
- **Table 1**: Attack detection performance (detection latency, mitigation effectiveness)
- **Table 2**: Safety comparison (defended vs undefended TTC and headway)

## Generating Figures

Requires matplotlib:

```bash
pip install matplotlib
python3 generate_figure.py
```

Outputs:
- `defense_comparison.pdf` - Publication-quality figure
- `defense_comparison.png` - Quick preview

## Attack Types

The benchmark tests 5 FDI attacks from peer-reviewed literature:

| Attack | Parameter | Source |
|--------|-----------|--------|
| constant | 0 m/s | van der Heijden |
| offset | +150 m/s | van der Heijden |
| replay | 3s delay | experimental |
| accel_offset | -30 m/s² | van der Heijden |
| accel_constant | +6 m/s² | Amoozadeh |

## Configuration

Edit `omnetpp.ini` to modify:
- Attack parameters (`attackType`, `attackMagnitude`, `attackStartTime`)
- Defense settings (`defenseEnabled`, `fusionAlpha`)
- Platoon configuration (size, spacing, controller type)
