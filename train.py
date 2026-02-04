import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from preprocess import clean_text

data = pd.read_csv("messages.csv", encoding="utf-8")

data = data.dropna(subset=["text", "label"]).copy()
data["text_clean"] = data["text"].astype(str).map(clean_text)
data = data[data["text_clean"].str.len() > 0]

X = data["text_clean"]
y = data["label"].astype(int)

# Vectorizer (word + bigrams). Keep settings easy to mirror in the offline JS app.
vectorizer = TfidfVectorizer(
    lowercase=True,
    token_pattern=r"(?u)\b\w\w+\b",
    ngram_range=(1, 2),
    max_features=8000,
)
X_vec = vectorizer.fit_transform(X)

# Model
model = LogisticRegression(max_iter=2000, class_weight="balanced")
model.fit(X_vec, y)

# Save correctly with joblib
joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

train_acc = float(model.score(X_vec, y))
print(f"Model and vectorizer saved successfully. Training accuracy: {train_acc:.3f}")
