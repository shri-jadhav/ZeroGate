"""
ZeroGate Cloud — DLP Evaluation & Benchmarking Suite
Evaluates the DLP engine against a labeled synthetic dataset of positive
and negative examples to compute confusion matrix, precision, and recall.
"""

from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from dlp.scanner import DLPScanner, ScanResult
from dlp.verhoeff import generate_synthetic_aadhaar


@dataclass
class EvaluationSample:
    sample_id: str
    text: str
    category: str
    expected_positive: bool
    expected_detectors: List[str]


def build_synthetic_evaluation_dataset() -> List[EvaluationSample]:
    """
    Builds a labeled, entirely synthetic benchmark dataset with both
    positive samples and realistic negative edge cases.
    """
    samples: List[EvaluationSample] = []

    # --------------------------------------------------------------------------
    # 1. Aadhaar Positive Samples (Valid Verhoeff checksums)
    # --------------------------------------------------------------------------
    # Generate authentic synthetic Verhoeff numbers
    aadhaar_1 = generate_synthetic_aadhaar("23456789012")  # 234567890124
    aadhaar_2 = generate_synthetic_aadhaar("98765432109")  # 987654321098
    aadhaar_3 = generate_synthetic_aadhaar("54321678901")  # 543216789016
    aadhaar_4 = generate_synthetic_aadhaar("36925814703")  # formatted with spaces
    aadhaar_5 = generate_synthetic_aadhaar("74185296307")  # formatted with hyphens

    samples.append(EvaluationSample(
        "aadhaar_pos_01", f"Customer verification submitted Aadhaar number: {aadhaar_1}",
        "Aadhaar", True, ["IN_AADHAAR"]
    ))
    samples.append(EvaluationSample(
        "aadhaar_pos_02", f"Identity record: UID {aadhaar_2} verified by registrar.",
        "Aadhaar", True, ["IN_AADHAAR"]
    ))
    samples.append(EvaluationSample(
        "aadhaar_pos_03", f"KYC doc ref: {aadhaar_3} for customer account opening.",
        "Aadhaar", True, ["IN_AADHAAR"]
    ))
    # Space-separated: 3692 5814 703X
    sp_fmt = f"{aadhaar_4[:4]} {aadhaar_4[4:8]} {aadhaar_4[8:]}"
    samples.append(EvaluationSample(
        "aadhaar_pos_04", f"Applicant Aadhaar ID is {sp_fmt} enclosed in application.",
        "Aadhaar", True, ["IN_AADHAAR"]
    ))
    # Hyphen-separated: 7418-8529-6307
    hy_fmt = f"{aadhaar_5[:4]}-{aadhaar_5[4:8]}-{aadhaar_5[8:]}"
    samples.append(EvaluationSample(
        "aadhaar_pos_05", f"Document serial {hy_fmt} matches central verification.",
        "Aadhaar", True, ["IN_AADHAAR"]
    ))

    # --------------------------------------------------------------------------
    # 2. Aadhaar Negative Samples (Edge cases, invalid checksums, false positive guards)
    # --------------------------------------------------------------------------
    # Invalid Verhoeff check digit (corrupted 12th digit)
    corrupted_aadhaar = aadhaar_1[:-1] + str((int(aadhaar_1[-1]) + 1) % 10)
    samples.append(EvaluationSample(
        "aadhaar_neg_01", f"Order tracking reference 12-digit number: {corrupted_aadhaar}",
        "Aadhaar", False, []
    ))
    # Starting with 0 or 1 (not valid Aadhaar)
    samples.append(EvaluationSample(
        "aadhaar_neg_02", "System internal transaction timestamp ID: 012345678901",
        "Aadhaar", False, []
    ))
    samples.append(EvaluationSample(
        "aadhaar_neg_03", "Legacy invoice sequence batch: 198765432109",
        "Aadhaar", False, []
    ))
    # Repeated digits dummy
    samples.append(EvaluationSample(
        "aadhaar_neg_04", "Test dummy pattern filled with 2222 2222 2222",
        "Aadhaar", False, []
    ))
    # 10-digit Indian Mobile phone number
    samples.append(EvaluationSample(
        "aadhaar_neg_05", "Please call the support desk at +91 9876543210 for queries.",
        "Aadhaar", False, []
    ))
    # 16-digit credit card number
    samples.append(EvaluationSample(
        "aadhaar_neg_06", "Card token reference: 4532 0150 1234 5678",
        "Aadhaar", False, []
    ))
    # Random 12-digit UPC barcode
    samples.append(EvaluationSample(
        "aadhaar_neg_07", "Inventory retail barcode scanned: 725272730706 on box.",
        "Aadhaar", False, []
    ))

    # --------------------------------------------------------------------------
    # 3. PAN Positive Samples (Valid entity structures)
    # --------------------------------------------------------------------------
    samples.append(EvaluationSample(
        "pan_pos_01", "Individual taxpayer PAN card: ABCPE1234F provided for TDS.",
        "PAN", True, ["IN_PAN"]
    ))
    samples.append(EvaluationSample(
        "pan_pos_02", "Corporate entity registration tax code: AAACC9876K.",
        "PAN", True, ["IN_PAN"]
    ))
    samples.append(EvaluationSample(
        "pan_pos_03", "Partnership firm declaration PAN: BKZPF5544R submitted.",
        "PAN", True, ["IN_PAN"]
    ))
    samples.append(EvaluationSample(
        "pan_pos_04", "Charitable Trust assessment record: DELTA1122M registered.",
        "PAN", True, ["IN_PAN"]
    ))
    samples.append(EvaluationSample(
        "pan_pos_05", "Government agency account identifier: GOVPG3321L active.",
        "PAN", True, ["IN_PAN"]
    ))

    # --------------------------------------------------------------------------
    # 4. PAN Negative Samples (Invalid syntax, bad 4th character, false alarms)
    # --------------------------------------------------------------------------
    # 4th character not in allowed set [PCHFATBLJG] (e.g., 'X')
    samples.append(EvaluationSample(
        "pan_neg_01", "Part number serialized as ABCXE1234F in technical drawing.",
        "PAN", False, []
    ))
    # 5 digits at end instead of 4
    samples.append(EvaluationSample(
        "pan_neg_02", "Flight cargo manifest code: ABCDE12345 received at port.",
        "PAN", False, []
    ))
    # Lowercase PAN (not standard tax identifier)
    samples.append(EvaluationSample(
        "pan_neg_03", "Internal variable name: abcde1234f = True in script.",
        "PAN", False, []
    ))
    # All zeros in serial digits
    samples.append(EvaluationSample(
        "pan_neg_04", "Template placeholder field: ABCDP0000Z in schema doc.",
        "PAN", False, []
    ))
    # Short alphanumeric string
    samples.append(EvaluationSample(
        "pan_neg_05", "Voucher promo discount code: ABCD123X applied.",
        "PAN", False, []
    ))

    # --------------------------------------------------------------------------
    # 5. API Keys & Secrets Positive Samples
    # --------------------------------------------------------------------------
    samples.append(EvaluationSample(
        "secret_pos_01", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
        "Secret", True, ["SECRET_AWS_KEY"]
    ))
    samples.append(EvaluationSample(
        "secret_pos_02", "GitHub CI bot credential: ghp_1234567890abcdefghijklmnopqrstuvwx",
        "Secret", True, ["SECRET_GITHUB_TOKEN"]
    ))
    samples.append(EvaluationSample(
        "secret_pos_03", "OpenAI integration key: sk-abcdef1234567890ABCDEF1234567890",
        "Secret", True, ["SECRET_OPENAI_KEY"]
    ))
    samples.append(EvaluationSample(
        "secret_pos_04", "Google Maps Platform key: AIzaSyD1234567890abcdefghijklmnopqrst",
        "Secret", True, ["SECRET_GOOGLE_KEY"]
    ))
    samples.append(EvaluationSample(
        "secret_pos_05", "ZeroGate canary auth token: zg_live_abcdef1234567890abcdef1234567890",
        "Secret", True, ["SECRET_ZEROGATE_TOKEN"]
    ))
    samples.append(EvaluationSample(
        "secret_pos_06", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Secret", True, ["SECRET_AWS_SECRET"]
    ))
    samples.append(EvaluationSample(
        "secret_pos_07", "api_key = abcdef1234567890abcdef1234567890",
        "Secret", True, ["SECRET_GENERIC_API_KEY"]
    ))

    # --------------------------------------------------------------------------
    # 6. API Keys Negative Samples (Normal code, UUIDs, git commit hashes, URLs)
    # --------------------------------------------------------------------------
    samples.append(EvaluationSample(
        "secret_neg_01", "Git commit hash 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b merged.",
        "Secret", False, []
    ))
    samples.append(EvaluationSample(
        "secret_neg_02", "Session UUID: 550e8400-e29b-41d4-a716-446655440000 created.",
        "Secret", False, []
    ))
    samples.append(EvaluationSample(
        "secret_neg_03", "Public endpoint URL: https://api.example.com/v1/users/list",
        "Secret", False, []
    ))
    samples.append(EvaluationSample(
        "secret_neg_04", "CSS background hex color: #2A8B3C with margin: 10px;",
        "Secret", False, []
    ))
    samples.append(EvaluationSample(
        "secret_neg_05", "Database connection host: postgres.internal.net:5432",
        "Secret", False, []
    ))

    # --------------------------------------------------------------------------
    # 7. Multi-Entity Mixed Samples
    # --------------------------------------------------------------------------
    mixed_aadhaar = generate_synthetic_aadhaar("88776655443")
    samples.append(EvaluationSample(
        "multi_pos_01",
        f"Employee onboarded: PAN AAACP1234K and Aadhaar {mixed_aadhaar} with API token zg_test_0123456789abcdef0123456789abcdef",
        "Multi-Match", True, ["IN_PAN", "IN_AADHAAR", "SECRET_ZEROGATE_TOKEN"]
    ))
    samples.append(EvaluationSample(
        "multi_neg_01",
        "Release notes v2.4.0: Fixed bug in invoice parser #1234, updated CSS #00FFAA, commit 9a8b7c6d.",
        "Benign", False, []
    ))

    return samples


def evaluate_dlp_engine(scanner: DLPScanner) -> Dict[str, Any]:
    """
    Evaluates DLPScanner against the synthetic benchmark dataset.
    Calculates True Positives, False Positives, True Negatives, False Negatives,
    Precision, Recall, and F1-Score.
    """
    dataset = build_synthetic_evaluation_dataset()

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    detailed_results = []

    for sample in dataset:
        result: ScanResult = scanner.scan_text(sample.text, context_id=sample.sample_id)
        predicted_positive = result.is_sensitive

        if sample.expected_positive and predicted_positive:
            tp += 1
            classification = "TP"
        elif not sample.expected_positive and predicted_positive:
            fp += 1
            classification = "FP"
        elif not sample.expected_positive and not predicted_positive:
            tn += 1
            classification = "TN"
        else:  # sample.expected_positive and not predicted_positive
            fn += 1
            classification = "FN"

        detailed_results.append({
            "sample_id": sample.sample_id,
            "category": sample.category,
            "expected_positive": sample.expected_positive,
            "predicted_positive": predicted_positive,
            "classification": classification,
            "decision": result.decision,
            "findings_count": result.total_findings_count,
        })

    total = len(dataset)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    return {
        "dataset_size": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "targets_met": {
            "precision_above_90": precision >= 0.90,
            "recall_above_85": recall >= 0.85,
        },
        "details": detailed_results,
    }


if __name__ == "__main__":
    scanner = DLPScanner()
    metrics = evaluate_dlp_engine(scanner)
    print("=" * 60)
    print("ZeroGate DLP Synthetic Benchmark Evaluation Results")
    print("=" * 60)
    print(f"Total Samples    : {metrics['dataset_size']}")
    print(f"True Positives   : {metrics['true_positives']}")
    print(f"False Positives  : {metrics['false_positives']}")
    print(f"True Negatives   : {metrics['true_negatives']}")
    print(f"False Negatives  : {metrics['false_negatives']}")
    print(f"Precision        : {metrics['precision'] * 100:.2f}% (Target: >90%)")
    print(f"Recall           : {metrics['recall'] * 100:.2f}% (Target: >85%)")
    print(f"F1-Score         : {metrics['f1_score'] * 100:.2f}%")
    print(f"Accuracy         : {metrics['accuracy'] * 100:.2f}%")
    print(f"Targets Satisfied: {metrics['targets_met']}")
    print("=" * 60)
