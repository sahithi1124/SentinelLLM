"""Generate the reproducible Phase 2 labeled evaluation report."""

import json
from pathlib import Path

from security.decision_engine import make_decision
from security.injection_detector import detect_injection
from security.input_normalizer import normalize_input
from security.risk_engine import calculate_risk

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "datasets" / "phase2_test_prompts.json"
REPORT = ROOT / "reports" / "phase2_evaluation.json"


def evaluate() -> dict:
    cases = json.loads(DATASET.read_text(encoding="utf-8"))
    confusion = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    details = []

    for case in cases:
        normalized = normalize_input(case["prompt"])
        detected = detect_injection(normalized.normalized)
        risk = calculate_risk(detected)
        decision = make_decision(risk.level)
        predicted_malicious = bool(risk.categories)
        expected_malicious = bool(case["malicious"])

        if predicted_malicious and expected_malicious:
            confusion["tp"] += 1
        elif not predicted_malicious and not expected_malicious:
            confusion["tn"] += 1
        elif predicted_malicious and not expected_malicious:
            confusion["fp"] += 1
        else:
            confusion["fn"] += 1

        details.append({"id": case["id"], "expected_malicious": expected_malicious,
                        "predicted_malicious": predicted_malicious,
                        "risk_score": risk.score, "decision": decision.decision})

    tp, tn, fp, fn = (confusion[key] for key in ("tp", "tn", "fp", "fn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if tp + tn + fp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    report = {"counts": {"total": len(cases), **confusion},
              "metrics": {"precision": round(precision, 4), "recall": round(recall, 4),
                          "f1": round(f1, 4), "accuracy": round(accuracy, 4)},
              "details": details,
              "caveat": "This small rule-based test set is not evidence of real-world effectiveness."}
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
