"""Append idempotent Phase 4–6 presentation cells without rerunning benchmarks."""
from pathlib import Path

import nbformat as nbf


path = Path("PQ-ZKAuth.ipynb")
notebook = nbf.read(path, as_version=4)
start = next((i for i, cell in enumerate(notebook.cells)
              if cell.get("source", "").startswith("# LIVE DEMONSTRATION")), len(notebook.cells))
notebook.cells = notebook.cells[:start]


def markdown(source: str) -> None:
    notebook.cells.append(nbf.v4.new_markdown_cell(source))


def code(source: str) -> None:
    notebook.cells.append(nbf.v4.new_code_cell(source))


markdown("# LIVE DEMONSTRATION\n"
         "This one-cell workflow uses the actual PQ-ZKAuth validator. It does not reveal private ML-DSA keys or credential scalars.")
code("demo = run_demo()\n"
     "print('SUCCESSFUL TRANSACTION')\n"
     "print('PQC Verification:', 'VALID' if demo['valid']['pqc_valid'] else 'FAILED')\n"
     "print('ZKP Verification:', 'VALID' if demo['valid']['zkp_valid'] else 'FAILED')\n"
     "print('Transaction:', 'ACCEPTED' if demo['valid']['accepted'] else 'REJECTED')\n"
     "print(f\"Block {demo['block_index']} added; hash: {demo['block_hash']}\")\n"
     "print('Blockchain integrity:', 'VALID' if demo['blockchain_valid'] else 'INVALID')\n"
     "print('\\nATTACK 1 — TAMPERED AMOUNT')\n"
     "print('PQC Verification:', 'VALID' if demo['tampered']['pqc_valid'] else 'FAILED')\n"
     "print('Transaction:', 'ACCEPTED' if demo['tampered']['accepted'] else 'REJECTED')\n"
     "print('\\nATTACK 2 — INVALID AUTHORIZATION PROOF')\n"
     "print('PQC Verification:', 'VALID' if demo['invalid_proof']['pqc_valid'] else 'FAILED')\n"
     "print('ZKP Verification:', 'VALID' if demo['invalid_proof']['zkp_valid'] else 'FAILED')\n"
     "print('Transaction:', 'ACCEPTED' if demo['invalid_proof']['accepted'] else 'REJECTED')\n"
     "display(demo['dashboard'].replace({True: '✓', False: '✗'}))")
markdown("# Phase 4 — Key Findings and Research Analysis\n"
         "The findings below are calculated from existing Phase 3 CSVs, not from a new benchmark run.")
code("from pathlib import Path\n"
     "phase4_results = Path('results')\n"
     "ablation_final = pd.read_csv(phase4_results / 'ablation_results.csv')\n"
     "scalability_final = pd.read_csv(phase4_results / 'scalability_results.csv')\n"
     "security_final = pd.read_csv(phase4_results / 'security_tests.csv')\n"
     "pqc_final = pd.read_csv(phase4_results / 'pqc_summary.csv')\n"
     "zkp_final = pd.read_csv(phase4_results / 'zkp_summary.csv')\n"
     "proposed_latency = ablation_final.loc[ablation_final.configuration == 'PQC + ZKP', 'end_to_end_ms'].iloc[0]\n"
     "pqc_latency = ablation_final.loc[ablation_final.configuration == 'PQC-only ML-DSA', 'end_to_end_ms'].iloc[0]\n"
     "baseline_latency = ablation_final.loc[ablation_final.configuration == 'Conventional ECDSA', 'end_to_end_ms'].iloc[0]\n"
     "zkp_increment = (proposed_latency - pqc_latency) / pqc_latency * 100\n"
     "baseline_overhead = (proposed_latency - baseline_latency) / baseline_latency * 100\n"
     "scale_first, scale_last = scalability_final.iloc[0], scalability_final.iloc[-1]\n"
     "latency_change = (scale_last.average_latency_ms - scale_first.average_latency_ms) / scale_first.average_latency_ms * 100\n"
     "findings = pd.DataFrame([\n"
     " {'Finding':'PQC signing dominates local signature cost','Evidence':f\"{pqc_final.loc[pqc_final.metric == 'signing_ms', 'mean_ms'].iloc[0]:.2f} ms mean vs {pqc_final.loc[pqc_final.metric == 'verification_ms', 'mean_ms'].iloc[0]:.2f} ms verification\",'Interpretation':'Signing is the largest isolated ML-DSA operation in this implementation.'},\n"
     " {'Finding':'Proof authorization has measurable cost','Evidence':f\"{zkp_final.loc[zkp_final.metric == 'proof_generation_ms', 'mean_ms'].iloc[0]:.3f} ms generation; {zkp_final.loc[zkp_final.metric == 'proof_verification_ms', 'mean_ms'].iloc[0]:.3f} ms verification\",'Interpretation':'Privacy-preserving authorization adds computation beyond signature-only validation.'},\n"
     " {'Finding':'ZKP increases PQC-only latency','Evidence':f\"{pqc_latency:.2f} to {proposed_latency:.2f} ms ({zkp_increment:.1f}%)\",'Interpretation':'The ablation isolates the local incremental cost of the proof layer.'},\n"
     " {'Finding':'PQC+ZKP exceeds local conventional baseline','Evidence':f\"{baseline_latency:.2f} to {proposed_latency:.2f} ms ({baseline_overhead:.1f}%)\",'Interpretation':'The added security and privacy properties come with measured local overhead.'},\n"
     " {'Finding':'Workload throughput is stable in tested range','Evidence':f\"{scale_first.throughput_tx_per_second:.1f}–{scale_last.throughput_tx_per_second:.1f} tx/s; latency change {latency_change:.2f}%\",'Interpretation':'Sequential processing was approximately linear from 10 to 1,000 transactions.'},\n"
     " {'Finding':'Attack checks behaved as designed','Evidence':f\"{int(security_final.passed.sum())}/{len(security_final)} validator cases matched expected outcomes\",'Interpretation':'The tested malformed, tampered, forged, and unauthorized inputs were rejected.'}])\n"
     "display(findings)")
markdown("## Security Findings and Trade-off Summary\n"
         "The validator tests establish correct behavior for the tested inputs, not a general security proof. ML-DSA protects the signed transaction fields; the proof protects the credential witness from direct disclosure. Costs include ML-DSA signature size, proof metadata, local computation, and key/credential management complexity. The classical secp256k1 proof is not post-quantum and remains the primary cryptographic limitation.")
code("security_dashboard = security_final.assign(\n"
     "    PQC=security_final.pqc_valid.map({True: '✓', False: '✗'}),\n"
     "    ZKP=security_final.zkp_valid.map({True: '✓', False: '✗'}),\n"
     "    Result=security_final.accepted.map({True: 'ACCEPT', False: 'REJECT'}))\n"
     "display(security_dashboard[['test', 'PQC', 'ZKP', 'Result', 'reason']])")
markdown("# Phase 6 — IEEE Readiness\n"
         "`docs/ieee_paper_outline.md` contains the paper-ready abstract, architecture, algorithms, methodology, six results tables, discussion, limitations, future work, and a preliminary reference list. The notebook and CSV files remain the authoritative source for every reported measurement.")

nbf.write(notebook, path)
