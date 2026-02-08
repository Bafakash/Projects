from __future__ import annotations

from pathlib import Path

import pandas as pd


def _read_csv_with_fallback(path: Path, encodings: tuple[str, ...]) -> pd.DataFrame:
    last_error: Exception | None = None
    for enc in encodings:
        try:
            return pd.read_csv(path, encoding=enc)
        except UnicodeDecodeError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    return pd.read_csv(path)


def _to_binary_label(value) -> int | None:
    if pd.isna(value):
        return None
    text = str(value).strip().lower()
    if text in {"1", "spam", "unsafe", "malicious", "phishing"}:
        return 1
    if text in {"0", "ham", "safe", "benign"}:
        return 0
    return None


def _prepare_messages_dataset(path: Path) -> pd.DataFrame:
    if not path.is_file():
        return pd.DataFrame(columns=["text", "label", "source"])

    data = _read_csv_with_fallback(path, ("utf-8", "utf-8-sig", "latin-1"))
    if "text" not in data.columns or "label" not in data.columns:
        raise ValueError(f"{path} must contain 'text' and 'label' columns.")

    out = pd.DataFrame()
    out["text"] = data["text"].astype(str)
    out["label"] = data["label"].map(_to_binary_label)
    out["source"] = "messages"
    return out


def _prepare_spam_dataset(path: Path) -> pd.DataFrame:
    if not path.is_file():
        return pd.DataFrame(columns=["text", "label", "source"])

    data = _read_csv_with_fallback(path, ("utf-8", "utf-8-sig", "latin-1"))

    text_col = "v2" if "v2" in data.columns else ("text" if "text" in data.columns else None)
    label_col = "v1" if "v1" in data.columns else ("label" if "label" in data.columns else None)
    if text_col is None or label_col is None:
        raise ValueError(f"{path} must contain either (v1,v2) or (label,text) columns.")

    out = pd.DataFrame()
    out["text"] = data[text_col].astype(str)
    out["label"] = data[label_col].map(_to_binary_label)
    out["source"] = "spam_csv"
    return out


def load_training_dataset(base_dir: str | Path = ".") -> pd.DataFrame:
    root = Path(base_dir)

    parts = [
        _prepare_messages_dataset(root / "messages.csv"),
        _prepare_spam_dataset(root / "spam" / "spam.csv"),
    ]

    data = pd.concat(parts, ignore_index=True)
    if data.empty:
        raise ValueError("No training rows were loaded.")

    data = data.dropna(subset=["text", "label"]).copy()
    data["text"] = data["text"].astype(str).str.strip()
    data = data[data["text"].str.len() > 0]
    data["label"] = data["label"].astype(int)

    # Keep one copy of exact duplicate rows.
    data = data.drop_duplicates(subset=["text", "label"], keep="first")
    data = data.reset_index(drop=True)
    return data

