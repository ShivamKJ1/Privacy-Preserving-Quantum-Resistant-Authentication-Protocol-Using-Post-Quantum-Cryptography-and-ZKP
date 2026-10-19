# PQ-ZKAuth

## Privacy-Preserving Quantum-Resistant Authentication for Blockchain Transactions

### Abstract

PQ-ZKAuth is an educational research prototype that combines ML-DSA-44 signatures for post-quantum transaction authentication with a transaction-bound Schnorr Fiat–Shamir proof for privacy-preserving authorization. A transaction is accepted only if both checks pass, then recorded in a SHA-256-linked local blockchain. In the saved 100-trial evaluation, the proposed normal-path latency averaged 7.33 ms; all six validator security cases and four blockchain-integrity cases matched their expected outcomes.

## Problem and objectives

Classical signatures authenticate a transaction sender but do not themselves provide post-quantum authentication or prove an authorization credential without exposing it. PQ-ZKAuth aims to:

- authenticate canonical transaction data with ML-DSA-44;
- prove knowledge of an authorization credential without transmitting its scalar secret;
- reject tampered, forged, malformed, and unauthorized transactions;
- record accepted transactions in a lightweight linked-block ledger; and
- quantify the security/privacy versus local-overhead trade-off.

## Proposed architecture

`PQCIdentity → canonical transaction → ML-DSA signature + Schnorr proof → PQZKValidator → SHA-256-linked block`

The validator checks required fields, the sender’s registered ML-DSA public key, and the sender’s registered public credential commitment. Private keys and credential scalars remain local.

## Technologies

- `pqcrypto==1.0.0`: ML-DSA-44 through PQClean-backed bindings.
- `ecdsa==0.19.2`: secp256k1 arithmetic for the Schnorr proof and ECDSA baseline.
- `pandas==3.0.6`, `matplotlib==3.11.1`: results tables and figures.
- `psutil==7.2.0`: reproducibility environment and memory observations.

## Installation and running the notebook

```powershell
python -m pip install -r requirements.txt
jupyter notebook PQ-ZKAuth.ipynb
```

Restart the kernel and choose **Run All Cells**. This regenerates the measured CSV files and figures. The complete paper-ready outline is in [docs/ieee_paper_outline.md](docs/ieee_paper_outline.md).

## Demo

The **LIVE DEMONSTRATION** section contains a one-cell `run_demo()` workflow:

1. Alice creates a transaction, ML-DSA signature, and authorization proof.
2. The validator accepts it and the chain adds a block.
3. A changed amount is rejected because the ML-DSA signature fails.
4. A malformed proof is rejected while the original ML-DSA signature remains valid.

Its compact dashboard is computed from actual validator outcomes; no result is pre-filled.

## Security tests

The saved test suite matched all expected outcomes:

| Scenario | Observed result |
|---|---|
| Valid transaction | accepted |
| Modified transaction | ML-DSA invalid; rejected |
| Invalid or wrong-user signature | ML-DSA invalid; rejected |
| Invalid proof | ZKP invalid; rejected |
| Valid PQC, unauthorized user | ZKP invalid; rejected |
| Altered chain record/header/link | chain invalid |

These tests demonstrate behavior for the tested cases; they are not a general security proof.

## Experimental evaluation

All Phase 3 operation/configuration benchmarks use 100 trials measured with `perf_counter_ns`; summary tables include mean, median, standard deviation, min/max, and normal-approximation 95% CI half-width. The test host was Windows 11, Python 3.14.7, 16 logical CPUs, approximately 16 GB RAM; no GPU was used.

| Metric | Latest saved result |
|---|---:|
| ML-DSA key generation / signing / verification | 0.096 / 4.94 / 0.090 ms |
| ZKP generation / verification | 0.725 / 1.75 ms |
| Proposed normal-path end-to-end | 7.33 ms |
| Conventional ECDSA / PQC-only / PQC+ZKP | 1.79 / 5.07 / 7.11 ms |
| Incremental ZKP cost vs PQC-only | 40.2% |
| PQC+ZKP overhead vs local ECDSA baseline | 298.2% |
| 1,000-transaction workload | 139.9 tx/s; 7.15 ms/tx; 1,000 accepted |

ML-DSA public/private/signature sizes are 1,312 / 2,560 / 2,420 bytes. The canonical serialized ZKP proof is 223 bytes. Results are local-machine measurements, not universal cryptographic rankings.

## Results, figures, and reproducibility

Raw data is retained under `results/`, including PQC, ZKP, end-to-end, baseline, ablation, scalability, security, integrity, environment, and trade-off CSVs. Generated charts are under `figures/`. The notebook is the authoritative reproducible workflow; `extend_phase3_notebook.py` and `extend_final_notebook.py` are its construction helpers.

## Limitations and future work

This is not a production cryptocurrency: it has no consensus/network layer, balances, persistent secure storage, credential revocation, anonymity, or real network latency. ML-DSA signatures and proof metadata add communication/storage cost. Most importantly, the Schnorr proof uses classical secp256k1, so PQC protection currently applies to authentication signatures, not the authorization proof.

Next work should evaluate a post-quantum proof construction, credential revocation, secure key lifecycle management, distributed/networked validation, larger workloads, and independent security review.

## Project structure

```text
PQ-ZKAuth.ipynb              runnable implementation, experiments, analysis, and demo
pq_zkauth.py                 protocol, validator, benchmark, and demo utilities
results/                     raw measurements and paper-ready CSV tables
figures/                     generated plots
docs/ieee_paper_outline.md   abstract, algorithms, tables, discussion, references
requirements.txt             pinned dependencies
```
