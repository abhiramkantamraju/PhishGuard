import argparse
import csv
import sys
from pathlib import Path

from detector import analyze_text, get_risk_level

# Real-world email bodies can exceed the csv module's default 128KB field
# size limit; raise it (capped to what the platform's C long supports).
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

PHISHING_LEVELS = {"Suspicious", "Dangerous"}


def normalize_label(label):
    value = label.strip().lower()
    if value in {"phishing", "phish", "malicious", "1", "true"}:
        return "phishing"
    if value in {"legitimate", "safe", "ham", "0", "false"}:
        return "legitimate"
    raise ValueError(f"Unsupported label: {label}")


def predict_label(email_text):
    flags, score = analyze_text(email_text)
    risk_level = get_risk_level(score)
    prediction = "phishing" if risk_level in PHISHING_LEVELS else "legitimate"
    return prediction, risk_level, score, flags


def read_rows(path):
    path = Path(path)

    if path.suffix.lower() == ".csv":
        with open(path, newline="", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            required_columns = {"label", "email_text"}
            missing_columns = required_columns - set(reader.fieldnames or [])
            if missing_columns:
                raise ValueError(f"CSV is missing required columns: {', '.join(sorted(missing_columns))}")
            yield from reader
        return

    if path.suffix.lower() == ".xlsx":
        from openpyxl import load_workbook

        workbook = load_workbook(path, read_only=True, data_only=True)
        sheet = workbook[workbook.sheetnames[0]]
        rows = sheet.iter_rows(values_only=True)
        headers = [str(value).strip() if value else "" for value in next(rows)]
        required_columns = {"label", "email_text"}
        missing_columns = required_columns - set(headers)
        if missing_columns:
            raise ValueError(f"XLSX is missing required columns: {', '.join(sorted(missing_columns))}")

        for row in rows:
            yield dict(zip(headers, row))
        return

    raise ValueError("Dataset must be a CSV or XLSX file.")


def evaluate_dataset(path, show_rows=True):
    total = 0
    correct = 0
    true_positive = 0
    false_positive = 0
    false_negative = 0

    for row in read_rows(path):
        actual = normalize_label(str(row["label"]))
        email_text = "" if row["email_text"] is None else str(row["email_text"])
        predicted, risk_level, score, flags = predict_label(email_text)

        total += 1
        if predicted == actual:
            correct += 1
            if predicted == "phishing":
                true_positive += 1
        elif predicted == "phishing" and actual == "legitimate":
            false_positive += 1
        elif predicted == "legitimate" and actual == "phishing":
            false_negative += 1

        if show_rows:
            print(
                f"{total}. actual={actual} predicted={predicted} "
                f"risk={risk_level} score={score} flags={len(flags)}"
            )

    accuracy = correct / total if total else 0
    false_positive_rate = false_positive / total if total else 0
    false_negative_rate = false_negative / total if total else 0
    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive) else 0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative) else 0
    )
    f1_score = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) else 0
    )

    return {
        "total": total,
        "correct": correct,
        "accuracy": accuracy,
        "false_positive": false_positive,
        "false_positive_rate": false_positive_rate,
        "false_negative": false_negative,
        "false_negative_rate": false_negative_rate,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate PhishGuard against a labeled email CSV.")
    parser.add_argument("csv_path", help="Path to a CSV with label and email_text columns.")
    parser.add_argument("--quiet", action="store_true", help="Only print the evaluation summary.")
    args = parser.parse_args()

    results = evaluate_dataset(args.csv_path, show_rows=not args.quiet)

    print("\nEvaluation summary")
    print(f"Total emails: {results['total']}")
    print(f"Correct predictions: {results['correct']}")
    print(f"Accuracy: {results['accuracy']:.2%}")
    print(f"False positives: {results['false_positive']} ({results['false_positive_rate']:.2%})")
    print(f"False negatives: {results['false_negative']} ({results['false_negative_rate']:.2%})")
    print(f"Precision: {results['precision']:.2%}")
    print(f"Recall: {results['recall']:.2%}")
    print(f"F1 score: {results['f1_score']:.2%}")


if __name__ == "__main__":
    main()
