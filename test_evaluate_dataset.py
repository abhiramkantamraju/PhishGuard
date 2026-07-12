import csv

from evaluate_dataset import evaluate_dataset, normalize_label


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["label", "email_text"])
        writer.writeheader()
        writer.writerows(rows)


class TestNormalizeLabel:
    def test_phishing_aliases(self):
        for value in ["phishing", "PHISHING", "phish", "malicious", "1", "true"]:
            assert normalize_label(value) == "phishing"

    def test_legitimate_aliases(self):
        for value in ["legitimate", "safe", "ham", "0", "false"]:
            assert normalize_label(value) == "legitimate"


class TestEvaluateDataset:
    def test_perfect_predictions_give_full_marks(self, tmp_path):
        csv_path = tmp_path / "perfect.csv"
        write_csv(csv_path, [
            {"label": "phishing", "email_text": "Urgent: verify your account now!"},
            {"label": "legitimate", "email_text": "Hi, just checking in about lunch."},
        ])

        results = evaluate_dataset(csv_path, show_rows=False)

        assert results["total"] == 2
        assert results["correct"] == 2
        assert results["accuracy"] == 1.0
        assert results["false_positive"] == 0
        assert results["false_negative"] == 0
        assert results["precision"] == 1.0
        assert results["recall"] == 1.0
        assert results["f1_score"] == 1.0

    def test_false_negative_lowers_recall_not_precision(self, tmp_path):
        csv_path = tmp_path / "fn.csv"
        write_csv(csv_path, [
            {"label": "phishing", "email_text": "Urgent: verify your account now!"},
            {"label": "phishing", "email_text": "no phishing signal here at all"},
            {"label": "legitimate", "email_text": "Hi, just checking in about lunch."},
        ])

        results = evaluate_dataset(csv_path, show_rows=False)

        assert results["false_negative"] == 1
        assert results["false_positive"] == 0
        assert results["precision"] == 1.0
        assert results["recall"] == 0.5
        assert round(results["f1_score"], 4) == round(2 * 1.0 * 0.5 / (1.0 + 0.5), 4)

    def test_false_positive_lowers_precision_not_recall(self, tmp_path):
        csv_path = tmp_path / "fp.csv"
        write_csv(csv_path, [
            {"label": "phishing", "email_text": "Urgent: verify your account now!"},
            {"label": "legitimate", "email_text": "Act now, limited time offer!"},
        ])

        results = evaluate_dataset(csv_path, show_rows=False)

        assert results["false_positive"] == 1
        assert results["false_negative"] == 0
        assert results["recall"] == 1.0
        assert results["precision"] == 0.5

    def test_empty_dataset_does_not_divide_by_zero(self, tmp_path):
        csv_path = tmp_path / "empty.csv"
        write_csv(csv_path, [])

        results = evaluate_dataset(csv_path, show_rows=False)

        assert results["total"] == 0
        assert results["accuracy"] == 0
        assert results["precision"] == 0
        assert results["recall"] == 0
        assert results["f1_score"] == 0
