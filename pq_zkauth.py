"""Core implementation for the PQ-ZKAuth Phase 2 demonstration.

ML-DSA-44 is provided by pqcrypto/PQClean.  Authorization uses a Schnorr
proof of knowledge over secp256k1, implemented with the audited ``ecdsa``
library's group arithmetic.  The proof is Fiat-Shamir non-interactive and is
bound to the canonical transaction payload.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import platform
import secrets
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from ecdsa import SECP256k1, SigningKey
from ecdsa.ellipticcurve import Point, PointJacobi
from pqcrypto import InvalidSignatureError
from pqcrypto.sign import ml_dsa_44


CURVE = SECP256k1
ORDER = CURVE.order
GENERATOR = CURVE.generator


def canonical_json(value: dict[str, Any]) -> bytes:
    """Return deterministic UTF-8 JSON used by signatures and hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def point_to_text(point: PointJacobi) -> str:
    """Serialize a public EC point; this is public, never a credential secret."""
    affine = point.to_affine()
    return f"{affine.x():064x}{affine.y():064x}"


def text_to_point(text: str) -> PointJacobi:
    if len(text) != 128:
        raise ValueError("invalid public-point encoding")
    x, y = int(text[:64], 16), int(text[64:], 16)
    return PointJacobi.from_affine(Point(CURVE.curve, x, y, ORDER))


@dataclass(frozen=True)
class ZKProof:
    """Public Schnorr/Fiat-Shamir proof; it contains no credential secret."""
    commitment: str
    response: str


@dataclass
class Transaction:
    transaction_id: str
    sender: str
    receiver: str
    amount: int
    timestamp: str
    nonce: str
    signature: str | None = None
    zk_proof: ZKProof | None = None

    def signing_payload(self) -> dict[str, Any]:
        return {"amount": self.amount, "nonce": self.nonce, "receiver": self.receiver,
                "sender": self.sender, "timestamp": self.timestamp, "transaction_id": self.transaction_id}

    def signing_bytes(self) -> bytes:
        return canonical_json(self.signing_payload())


@dataclass
class PQCIdentity:
    """Identity with an ML-DSA keypair and local-only authorization witness."""
    user_id: str
    public_key: bytes
    _private_key: bytes = field(repr=False)
    _credential_secret: int = field(repr=False)

    @classmethod
    def generate(cls, user_id: str) -> "PQCIdentity":
        public_key, private_key = ml_dsa_44.keygen()
        return cls(user_id, public_key, private_key, secrets.randbelow(ORDER - 1) + 1)

    @property
    def credential_commitment(self) -> str:
        return point_to_text(GENERATOR * self._credential_secret)

    def sign_transaction(self, transaction: Transaction) -> None:
        transaction.signature = b64(ml_dsa_44.sign(self._private_key, transaction.signing_bytes()))

    def prove_authorization(self, transaction: Transaction) -> ZKProof:
        """Create Schnorr proof: sG = R + H(context,R) * credential_public."""
        nonce = secrets.randbelow(ORDER - 1) + 1
        commitment = point_to_text(GENERATOR * nonce)
        challenge = _challenge(transaction, self.credential_commitment, commitment)
        response = (nonce + challenge * self._credential_secret) % ORDER
        return ZKProof(commitment=commitment, response=f"{response:064x}")


def _challenge(transaction: Transaction, credential_commitment: str, proof_commitment: str) -> int:
    transcript = {"credential_commitment": credential_commitment, "proof_commitment": proof_commitment,
                  "transaction": transaction.signing_payload(), "domain": "PQ-ZKAuth/Schnorr-v1"}
    return int.from_bytes(hashlib.sha256(canonical_json(transcript)).digest(), "big") % ORDER


def verify_signature(transaction: Transaction, public_key: bytes) -> bool:
    if not transaction.signature:
        return False
    try:
        ml_dsa_44.verify(public_key, transaction.signing_bytes(), base64.b64decode(transaction.signature, validate=True))
        return True
    except (InvalidSignatureError, ValueError, TypeError):
        # Malformed external transaction data is invalid rather than exceptional.
        return False


def verify_zk_proof(transaction: Transaction, credential_commitment: str | None) -> bool:
    if credential_commitment is None or transaction.zk_proof is None:
        return False
    try:
        proof = transaction.zk_proof
        response = int(proof.response, 16)
        if not 0 <= response < ORDER:
            return False
        public = text_to_point(credential_commitment)
        commitment = text_to_point(proof.commitment)
        challenge = _challenge(transaction, credential_commitment, proof.commitment)
        # Point equality handles the point at infinity safely for malformed proofs.
        return GENERATOR * response == commitment + public * challenge
    except (ValueError, AssertionError, TypeError):
        return False


@dataclass
class ValidationResult:
    pqc_valid: bool
    zkp_valid: bool
    transaction_valid: bool
    accepted: bool
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class PQZKValidator:
    def __init__(self, public_keys: dict[str, bytes], authorized_credentials: dict[str, str]):
        self.public_keys = public_keys
        self.authorized_credentials = authorized_credentials

    def validate_transaction(self, transaction: Transaction) -> ValidationResult:
        transaction_valid = (isinstance(transaction.amount, int) and transaction.amount > 0
                             and bool(transaction.transaction_id) and bool(transaction.sender)
                             and bool(transaction.receiver) and bool(transaction.timestamp) and bool(transaction.nonce))
        pqc_valid = verify_signature(transaction, self.public_keys[transaction.sender]) if transaction.sender in self.public_keys else False
        zkp_valid = verify_zk_proof(transaction, self.authorized_credentials.get(transaction.sender))
        accepted = transaction_valid and pqc_valid and zkp_valid
        reason = "Authentication and authorization successful" if accepted else (
            "Invalid transaction fields" if not transaction_valid else "ML-DSA signature invalid" if not pqc_valid else "Authorization proof invalid")
        return ValidationResult(pqc_valid, zkp_valid, transaction_valid, accepted, reason)


@dataclass
class Block:
    index: int
    timestamp: str
    transactions: list[dict[str, Any]]
    previous_hash: str
    hash: str = ""

    def compute_hash(self) -> str:
        data = {"index": self.index, "previous_hash": self.previous_hash, "timestamp": self.timestamp,
                "transactions": self.transactions}
        return hashlib.sha256(canonical_json(data)).hexdigest()


class Blockchain:
    def __init__(self) -> None:
        genesis = Block(0, "1970-01-01T00:00:00+00:00", [], "0")
        genesis.hash = genesis.compute_hash()
        self.chain = [genesis]

    def add_block(self, transactions: list[Transaction]) -> Block:
        records = [asdict(tx) for tx in transactions]
        block = Block(len(self.chain), datetime.now(timezone.utc).isoformat(), records, self.chain[-1].hash)
        block.hash = block.compute_hash()
        self.chain.append(block)
        return block

    def validate_chain(self) -> bool:
        return all(block.hash == block.compute_hash() and (i == 0 or block.previous_hash == self.chain[i - 1].hash)
                   for i, block in enumerate(self.chain))


def create_signed_transaction(identity: PQCIdentity, receiver: str, amount: int, transaction_id: str | None = None) -> Transaction:
    tx = Transaction(transaction_id or secrets.token_hex(16), identity.user_id, receiver, amount,
                     datetime.now(timezone.utc).isoformat(), secrets.token_hex(12))
    identity.sign_transaction(tx)
    tx.zk_proof = identity.prove_authorization(tx)
    return tx


def clone_transaction(transaction: Transaction) -> Transaction:
    return copy.deepcopy(transaction)


def benchmark(trials: int = 20) -> tuple[dict[str, dict[str, float]], Any]:
    """Run actual cryptographic trials and return summary and raw Pandas table."""
    import pandas as pd
    rows: list[dict[str, float]] = []
    for i in range(trials):
        start = time.perf_counter_ns(); user = PQCIdentity.generate(f"bench-{i}"); keygen = time.perf_counter_ns() - start
        tx = Transaction(f"b-{i}", user.user_id, "treasury", 10, "2026-01-01T00:00:00+00:00", f"n-{i}")
        start = time.perf_counter_ns(); user.sign_transaction(tx); signing = time.perf_counter_ns() - start
        start = time.perf_counter_ns(); tx.zk_proof = user.prove_authorization(tx); proof_gen = time.perf_counter_ns() - start
        validator = PQZKValidator({user.user_id: user.public_key}, {user.user_id: user.credential_commitment})
        start = time.perf_counter_ns(); result = validator.validate_transaction(tx); validation = time.perf_counter_ns() - start
        if not result.accepted:
            raise RuntimeError("benchmark transaction unexpectedly rejected")
        # Individually time the actual verifier operations.
        start = time.perf_counter_ns(); verify_signature(tx, user.public_key); signature_verify = time.perf_counter_ns() - start
        start = time.perf_counter_ns(); verify_zk_proof(tx, user.credential_commitment); proof_verify = time.perf_counter_ns() - start
        chain = Blockchain(); start = time.perf_counter_ns(); chain.add_block([tx]); block_creation = time.perf_counter_ns() - start
        rows.append({"PQC key generation": keygen / 1e6, "PQC signing": signing / 1e6,
                     "PQC verification": signature_verify / 1e6, "ZKP generation": proof_gen / 1e6,
                     "ZKP verification": proof_verify / 1e6, "Transaction validation": validation / 1e6,
                     "Block creation": block_creation / 1e6, "End-to-end": (keygen + signing + proof_gen + validation) / 1e6})
    frame = pd.DataFrame(rows)
    summary = {column: {stat: float(frame[column].agg(stat)) for stat in ("mean", "median", "std", "min", "max")}
               for column in frame.columns}
    return summary, frame


def summarize_measurements(frame: Any) -> Any:
    """Return descriptive statistics and normal-approximation 95% CIs in ms."""
    import pandas as pd
    numeric = frame.select_dtypes(include="number")
    rows = []
    for column in numeric.columns:
        values = numeric[column]
        ci = 1.96 * values.std(ddof=1) / (len(values) ** 0.5) if len(values) > 1 else 0.0
        rows.append({"metric": column, "mean_ms": values.mean(), "median_ms": values.median(),
                     "std_ms": values.std(ddof=1), "min_ms": values.min(), "max_ms": values.max(),
                     "ci95_half_width_ms": ci, "trials": len(values)})
    return pd.DataFrame(rows)


def benchmark_pqc(trials: int = 100) -> Any:
    """Independently measure real ML-DSA-44 operations; all times are ms."""
    import pandas as pd
    rows = []
    for i in range(trials):
        start = time.perf_counter_ns(); public_key, private_key = ml_dsa_44.keygen(); keygen = time.perf_counter_ns() - start
        message = canonical_json({"benchmark": "pqc", "trial": i})
        start = time.perf_counter_ns(); signature = ml_dsa_44.sign(private_key, message); signing = time.perf_counter_ns() - start
        start = time.perf_counter_ns(); ml_dsa_44.verify(public_key, message, signature); verification = time.perf_counter_ns() - start
        rows.append({"trial": i + 1, "key_generation_ms": keygen / 1e6, "signing_ms": signing / 1e6,
                     "verification_ms": verification / 1e6, "public_key_bytes": len(public_key),
                     "private_key_bytes": len(private_key), "signature_bytes": len(signature)})
    return pd.DataFrame(rows)


def benchmark_zkp(trials: int = 100) -> Any:
    """Independently measure actual Schnorr proof generation and verification."""
    import pandas as pd
    user = PQCIdentity.generate("zkp-benchmark")
    rows = []
    for i in range(trials):
        tx = Transaction(f"zkp-{i}", user.user_id, "resource", 1, "2026-01-01T00:00:00+00:00", f"n-{i}")
        start = time.perf_counter_ns(); proof = user.prove_authorization(tx); generation = time.perf_counter_ns() - start
        tx.zk_proof = proof
        start = time.perf_counter_ns(); valid = verify_zk_proof(tx, user.credential_commitment); verification = time.perf_counter_ns() - start
        if not valid:
            raise RuntimeError("generated ZKP did not verify")
        proof_bytes = len(canonical_json(asdict(proof)))
        rows.append({"trial": i + 1, "proof_generation_ms": generation / 1e6,
                     "proof_verification_ms": verification / 1e6, "proof_bytes": proof_bytes})
    return pd.DataFrame(rows)


def benchmark_end_to_end(trials: int = 100) -> Any:
    """Measure the proposed protocol from transaction construction through chain validation."""
    import pandas as pd
    user = PQCIdentity.generate("e2e-user")
    validator = PQZKValidator({user.user_id: user.public_key}, {user.user_id: user.credential_commitment})
    rows = []
    for i in range(trials):
        tx = Transaction(f"e2e-{i}", user.user_id, "merchant", 10, "2026-01-01T00:00:00+00:00", f"n-{i}")
        start = time.perf_counter_ns(); user.sign_transaction(tx); signing = time.perf_counter_ns() - start
        start = time.perf_counter_ns(); tx.zk_proof = user.prove_authorization(tx); proof_generation = time.perf_counter_ns() - start
        start = time.perf_counter_ns(); signature_valid = verify_signature(tx, user.public_key); signature_verification = time.perf_counter_ns() - start
        start = time.perf_counter_ns(); proof_valid = verify_zk_proof(tx, user.credential_commitment); proof_verification = time.perf_counter_ns() - start
        start = time.perf_counter_ns(); result = validator.validate_transaction(tx); validation = time.perf_counter_ns() - start
        chain = Blockchain(); start = time.perf_counter_ns(); chain.add_block([tx]); chain_valid = chain.validate_chain(); blockchain = time.perf_counter_ns() - start
        if not (signature_valid and proof_valid and result.accepted and chain_valid):
            raise RuntimeError("end-to-end benchmark transaction unexpectedly failed")
        # Normal protocol latency invokes the validator once; the two isolated
        # verifier timings above are diagnostic measurements and are not added
        # again, avoiding double-counting validation in the end-to-end metric.
        total = signing + proof_generation + validation + blockchain
        rows.append({"trial": i + 1, "pqc_signing_ms": signing / 1e6, "zkp_generation_ms": proof_generation / 1e6,
                     "pqc_verification_ms": signature_verification / 1e6, "zkp_verification_ms": proof_verification / 1e6,
                     "validator_ms": validation / 1e6, "blockchain_ms": blockchain / 1e6, "end_to_end_ms": total / 1e6})
    return pd.DataFrame(rows)


def _baseline_transaction(i: int) -> Transaction:
    return Transaction(f"base-{i}", "baseline", "merchant", 10, "2026-01-01T00:00:00+00:00", f"n-{i}")


def compare_configurations(trials: int = 100) -> Any:
    """Compare conventional ECDSA, PQC-only ML-DSA, and proposed PQC+ZKP fairly."""
    import pandas as pd
    conventional_key = SigningKey.generate(curve=SECP256k1)
    conventional_verify_key = conventional_key.verifying_key
    pqc_user = PQCIdentity.generate("comparison-user")
    pqc_validator = PQZKValidator({pqc_user.user_id: pqc_user.public_key}, {pqc_user.user_id: pqc_user.credential_commitment})
    rows = []
    for i in range(trials):
        base_tx = _baseline_transaction(i)
        start_total = time.perf_counter_ns(); start = time.perf_counter_ns()
        baseline_sig = conventional_key.sign_deterministic(base_tx.signing_bytes(), hashfunc=hashlib.sha256)
        auth = time.perf_counter_ns() - start; start = time.perf_counter_ns()
        baseline_valid = conventional_verify_key.verify(baseline_sig, base_tx.signing_bytes(), hashfunc=hashlib.sha256)
        verify = time.perf_counter_ns() - start; total = time.perf_counter_ns() - start_total
        if not baseline_valid:
            raise RuntimeError("baseline signature unexpectedly failed")
        rows.append({"trial": i + 1, "configuration": "Conventional ECDSA", "authentication_ms": auth / 1e6,
                     "verification_ms": verify / 1e6, "end_to_end_ms": total / 1e6, "communication_bytes": len(baseline_sig)})

        pqc_tx = Transaction(f"pqc-{i}", pqc_user.user_id, "merchant", 10, "2026-01-01T00:00:00+00:00", f"n-{i}")
        start_total = time.perf_counter_ns(); start = time.perf_counter_ns(); pqc_user.sign_transaction(pqc_tx); auth = time.perf_counter_ns() - start
        start = time.perf_counter_ns(); valid = verify_signature(pqc_tx, pqc_user.public_key); verify = time.perf_counter_ns() - start; total = time.perf_counter_ns() - start_total
        if not valid:
            raise RuntimeError("PQC-only signature unexpectedly failed")
        rows.append({"trial": i + 1, "configuration": "PQC-only ML-DSA", "authentication_ms": auth / 1e6,
                     "verification_ms": verify / 1e6, "end_to_end_ms": total / 1e6,
                     "communication_bytes": len(base64.b64decode(pqc_tx.signature))})

        proposed_tx = Transaction(f"proposed-{i}", pqc_user.user_id, "merchant", 10, "2026-01-01T00:00:00+00:00", f"n-{i}")
        start_total = time.perf_counter_ns(); start = time.perf_counter_ns(); pqc_user.sign_transaction(proposed_tx); proposed_tx.zk_proof = pqc_user.prove_authorization(proposed_tx); auth = time.perf_counter_ns() - start
        start = time.perf_counter_ns(); valid = pqc_validator.validate_transaction(proposed_tx).accepted; verify = time.perf_counter_ns() - start; total = time.perf_counter_ns() - start_total
        if not valid:
            raise RuntimeError("proposed transaction unexpectedly failed")
        proof_bytes = len(canonical_json(asdict(proposed_tx.zk_proof)))
        rows.append({"trial": i + 1, "configuration": "PQC + ZKP", "authentication_ms": auth / 1e6,
                     "verification_ms": verify / 1e6, "end_to_end_ms": total / 1e6,
                     "communication_bytes": len(base64.b64decode(proposed_tx.signature)) + proof_bytes})
    return pd.DataFrame(rows)


def run_security_tests() -> Any:
    """Run a structured set of positive and negative authentication tests."""
    import pandas as pd
    alice, bob, mallory = PQCIdentity.generate("alice"), PQCIdentity.generate("bob"), PQCIdentity.generate("mallory")
    validator = PQZKValidator({"alice": alice.public_key, "bob": bob.public_key}, {"alice": alice.credential_commitment})
    valid = create_signed_transaction(alice, "merchant", 10, "security-valid")
    tampered = clone_transaction(valid); tampered.amount = 100
    invalid_signature = clone_transaction(valid); invalid_signature.signature = b64(secrets.token_bytes(ml_dsa_44.SIGNATURE_SIZE))
    wrong_user = clone_transaction(valid); mallory.sign_transaction(wrong_user)
    invalid_proof = clone_transaction(valid); invalid_proof.zk_proof = ZKProof(invalid_proof.zk_proof.commitment, "00" * 32)
    unauthorized = create_signed_transaction(bob, "merchant", 10, "security-bob")
    cases = [("Valid transaction", valid, True), ("Modified transaction", tampered, False),
             ("Invalid signature", invalid_signature, False), ("Wrong user", wrong_user, False),
             ("Invalid ZKP", invalid_proof, False), ("Valid PQC but unauthorized user", unauthorized, False)]
    rows = []
    for name, tx, expected in cases:
        result = validator.validate_transaction(tx)
        rows.append({"test": name, "expected_accepted": expected, "pqc_valid": result.pqc_valid,
                     "zkp_valid": result.zkp_valid, "accepted": result.accepted,
                     "passed": result.accepted == expected, "reason": result.reason})
    return pd.DataFrame(rows)


def run_blockchain_integrity_tests() -> Any:
    """Show that independently hashed chain records detect ledger mutations."""
    import pandas as pd
    user = PQCIdentity.generate("chain-user")
    tx = create_signed_transaction(user, "merchant", 10, "chain-tx")
    original = Blockchain(); original.add_block([tx])
    cases: list[tuple[str, Blockchain]] = [("Valid chain", original)]
    tx_modified = copy.deepcopy(original); tx_modified.chain[1].transactions[0]["amount"] = 99
    cases.append(("Modified transaction record", tx_modified))
    block_modified = copy.deepcopy(original); block_modified.chain[1].timestamp = "altered"
    cases.append(("Modified block header", block_modified))
    broken_link = copy.deepcopy(original); broken_link.chain[1].previous_hash = "0" * 64
    cases.append(("Broken previous-hash link", broken_link))
    return pd.DataFrame([{"test": name, "chain_valid": chain.validate_chain(), "expected_valid": name == "Valid chain"}
                         for name, chain in cases]).assign(passed=lambda data: data.chain_valid == data.expected_valid)


def run_scalability_test(workloads: tuple[int, ...] = (10, 50, 100, 250, 500, 1000)) -> Any:
    """Process real proposed transactions at several workloads; times are wall-clock ms."""
    import pandas as pd
    try:
        import psutil
        process = psutil.Process(os.getpid())
    except ImportError:
        process = None
    user = PQCIdentity.generate("scale-user")
    validator = PQZKValidator({user.user_id: user.public_key}, {user.user_id: user.credential_commitment})
    rows = []
    for count in workloads:
        start_memory = process.memory_info().rss if process else None
        start = time.perf_counter_ns(); accepted: list[Transaction] = []; rejected = 0
        for i in range(count):
            tx = create_signed_transaction(user, "merchant", 10, f"scale-{count}-{i}")
            if validator.validate_transaction(tx).accepted:
                accepted.append(tx)
            else:
                rejected += 1
        chain = Blockchain(); chain.add_block(accepted)
        elapsed_ms = (time.perf_counter_ns() - start) / 1e6
        end_memory = process.memory_info().rss if process else None
        rows.append({"workload_transactions": count, "total_processing_ms": elapsed_ms,
                     "average_latency_ms": elapsed_ms / count, "throughput_tx_per_second": count / (elapsed_ms / 1000),
                     "successful_transactions": len(accepted), "rejected_transactions": rejected,
                     "memory_delta_bytes": (end_memory - start_memory) if process else None,
                     "chain_valid": chain.validate_chain()})
    return pd.DataFrame(rows)


def environment_details(trials: int) -> dict[str, Any]:
    """Capture reproducibility information for a CPU-oriented experiment run."""
    import ecdsa
    import pandas as pd
    import matplotlib
    import pqcrypto
    details: dict[str, Any] = {"python": sys.version.split()[0], "platform": platform.platform(),
                               "processor": platform.processor() or "not reported", "cpu_count": os.cpu_count(),
                               "pqcrypto": getattr(pqcrypto, "__version__", "1.0.0"), "ecdsa": ecdsa.__version__,
                               "pandas": pd.__version__, "matplotlib": matplotlib.__version__, "trial_count": trials,
                               "gpu_used": False, "workload": "CPU-oriented cryptographic prototype"}
    try:
        import psutil
        details["ram_bytes"] = psutil.virtual_memory().total
    except ImportError:
        details["ram_bytes"] = "not available"
    return details


def run_demo() -> dict[str, Any]:
    """Run a compact, real end-to-end demonstration and selected attacks.

    The return value is presentation-friendly but derives every status from the
    same validator used by the notebook; no outcome is pre-filled.
    """
    import pandas as pd

    alice = PQCIdentity.generate("alice")
    bob = PQCIdentity.generate("bob")
    validator = PQZKValidator({alice.user_id: alice.public_key, bob.user_id: bob.public_key},
                               {alice.user_id: alice.credential_commitment})
    chain = Blockchain()
    valid = create_signed_transaction(alice, "merchant", 10, "live-demo-valid")
    valid_result = validator.validate_transaction(valid)
    if not valid_result.accepted:
        raise RuntimeError("live demonstration valid transaction was rejected")
    block = chain.add_block([valid])

    tampered = clone_transaction(valid)
    tampered.amount = 100
    tampered_result = validator.validate_transaction(tampered)

    invalid_proof = clone_transaction(valid)
    invalid_proof.zk_proof = ZKProof(invalid_proof.zk_proof.commitment, "00" * 32)
    invalid_proof_result = validator.validate_transaction(invalid_proof)
    unauthorized = create_signed_transaction(bob, "merchant", 10, "live-demo-unauthorized")
    unauthorized_result = validator.validate_transaction(unauthorized)

    dashboard = pd.DataFrame([
        {"Test": "Valid transaction", "PQC": valid_result.pqc_valid, "ZKP": valid_result.zkp_valid,
         "Result": "ACCEPT" if valid_result.accepted else "REJECT"},
        {"Test": "Tampered transaction", "PQC": tampered_result.pqc_valid, "ZKP": tampered_result.zkp_valid,
         "Result": "ACCEPT" if tampered_result.accepted else "REJECT"},
        {"Test": "Invalid proof", "PQC": invalid_proof_result.pqc_valid, "ZKP": invalid_proof_result.zkp_valid,
         "Result": "ACCEPT" if invalid_proof_result.accepted else "REJECT"},
        {"Test": "Unauthorized user", "PQC": unauthorized_result.pqc_valid, "ZKP": unauthorized_result.zkp_valid,
         "Result": "ACCEPT" if unauthorized_result.accepted else "REJECT"},
    ])
    return {"valid": valid_result.as_dict(), "tampered": tampered_result.as_dict(),
            "invalid_proof": invalid_proof_result.as_dict(), "unauthorized": unauthorized_result.as_dict(), "block_index": block.index,
            "block_hash": block.hash, "blockchain_valid": chain.validate_chain(), "dashboard": dashboard}
