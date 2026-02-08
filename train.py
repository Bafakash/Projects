from __future__ import annotations

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from dataset_loader import load_training_dataset
from preprocess import clean_text

SOURCE_SAMPLE_WEIGHTS = {
    # Keep user-curated bilingual rows influential so Arabic phishing indicators are not drowned out.
    "messages": 4.0,
    "spam_csv": 1.0,
}
RANDOM_STATE = 42


def _source_weights(source_series):
    return source_series.map(lambda s: SOURCE_SAMPLE_WEIGHTS.get(str(s), 1.0)).astype(float)


def _safe_preview(text: str, limit: int = 140) -> str:
    value = " ".join(str(text or "").split())
    if len(value) > limit:
        value = value[: limit - 3] + "..."
    return value.encode("ascii", errors="backslashreplace").decode("ascii")


def _print_error_examples(title: str, rows, true_label: int, pred_label: int) -> None:
    mask = (rows["true_label"] == true_label) & (rows["pred_label"] == pred_label)
    subset = rows[mask].copy()
    if subset.empty:
        print(f"{title}: none")
        return

    subset = subset.sort_values("unsafe_proba", ascending=(true_label == 1))
    print(f"{title}: {len(subset)}")
    for _, r in subset.head(8).iterrows():
        print(f"  - p(unsafe)={r['unsafe_proba']:.3f} | {_safe_preview(r['text'])}")


def main() -> None:
    data = load_training_dataset(".")
    data["text_clean"] = data["text"].astype(str).map(clean_text)
    data = data[data["text_clean"].str.len() > 0].copy()

    if data["label"].nunique() < 2:
        raise SystemExit("Training data must contain both safe(0) and unsafe(1) labels.")

    print("Dataset loaded.")
    print(f"Rows: {len(data)}")
    print(f"Labels: {data['label'].value_counts().to_dict()}")
    print(f"Sources: {data['source'].value_counts().to_dict()}")

    train_df, val_df = train_test_split(
        data,
        test_size=0.2,
        stratify=data["label"],
        random_state=RANDOM_STATE,
    )

    vectorizer_eval = TfidfVectorizer(
        lowercase=True,
        token_pattern=r"(?u)\b\w\w+\b",
        ngram_range=(1, 2),
        max_features=8000,
    )
    X_train = vectorizer_eval.fit_transform(train_df["text_clean"])
    X_val = vectorizer_eval.transform(val_df["text_clean"])

    model_eval = LogisticRegression(max_iter=2500, class_weight="balanced", random_state=RANDOM_STATE)
    model_eval.fit(X_train, train_df["label"], sample_weight=_source_weights(train_df["source"]))

    y_true = val_df["label"].astype(int).to_numpy()
    y_pred = model_eval.predict(X_val).astype(int)

    class_to_idx = {int(c): i for i, c in enumerate(getattr(model_eval, "classes_", [0, 1]))}
    unsafe_idx = class_to_idx.get(1, 1 if len(model_eval.classes_) > 1 else 0)
    y_prob = model_eval.predict_proba(X_val)[:, unsafe_idx]

    print("\nValidation report (combined datasets):")
    print(classification_report(y_true, y_pred, digits=3, zero_division=0))
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    print("Confusion matrix [[tn, fp], [fn, tp]]:", cm.tolist())

    mistakes = val_df[["text"]].copy().reset_index(drop=True)
    mistakes["true_label"] = y_true
    mistakes["pred_label"] = y_pred
    mistakes["unsafe_proba"] = y_prob

    print("\nMistake analysis:")
    _print_error_examples("False negatives (unsafe predicted safe)", mistakes, true_label=1, pred_label=0)
    _print_error_examples("False positives (safe predicted unsafe)", mistakes, true_label=0, pred_label=1)

    # Train final production model on the full combined dataset.
    vectorizer = TfidfVectorizer(
        lowercase=True,
        token_pattern=r"(?u)\b\w\w+\b",
        ngram_range=(1, 2),
        max_features=8000,
    )
    X_all = vectorizer.fit_transform(data["text_clean"])
    model = LogisticRegression(max_iter=2500, class_weight="balanced", random_state=RANDOM_STATE)
    model.fit(X_all, data["label"], sample_weight=_source_weights(data["source"]))

    joblib.dump(model, "model.pkl")
    joblib.dump(vectorizer, "vectorizer.pkl")

    train_acc = float(model.score(X_all, data["label"]))
    print(f"\nSaved model.pkl + vectorizer.pkl. Full-data training accuracy: {train_acc:.3f}")


if __name__ == "__main__":
    main()
