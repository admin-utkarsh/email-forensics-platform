import os
import json
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)

import joblib


# ============================================================
# CONFIG
# ============================================================

DATASET = r"datasets\raw\phishing_legit_dataset_KD_10000.csv"

MODEL_DIR = r"ml\model"
REPORT_DIR = r"ml\reports"

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


# ============================================================
# LOAD DATASET
# ============================================================

print("\n========================================")
print("MAILTRACE AI - MODEL TRAINING")
print("========================================\n")

print("[1/7] Loading dataset...")

df = pd.read_csv(DATASET)

print(f"Rows: {len(df)}")
print(f"Columns: {list(df.columns)}")


# ============================================================
# VALIDATE COLUMNS
# ============================================================

required_columns = ["text", "label"]

for column in required_columns:
    if column not in df.columns:
        raise ValueError(
            f"Required column '{column}' not found.\n"
            f"Available columns: {list(df.columns)}"
        )


# ============================================================
# CLEAN DATA
# ============================================================

print("\n[2/7] Cleaning data...")

df["text"] = df["text"].fillna("").astype(str)

df["label"] = pd.to_numeric(
    df["label"],
    errors="coerce"
)

df = df.dropna(subset=["label"])

df["label"] = df["label"].astype(int)

# Keep only binary labels
df = df[df["label"].isin([0, 1])]

# Remove empty emails
df = df[df["text"].str.strip().str.len() > 0]

# Remove duplicate emails
before = len(df)

df = df.drop_duplicates(
    subset=["text"]
)

after = len(df)

print(f"Removed duplicates: {before - after}")
print(f"Final rows: {len(df)}")


# ============================================================
# LABEL DISTRIBUTION
# ============================================================

print("\n[3/7] Checking labels...")

print("\nLabel distribution:")

print(
    df["label"]
    .value_counts()
    .sort_index()
)

print("\n0 = Legitimate")
print("1 = Phishing")


# Make sure both classes exist
if df["label"].nunique() < 2:
    raise ValueError(
        "Dataset contains only one class. "
        "Training requires both legitimate and phishing emails."
    )


# ============================================================
# FEATURES
# ============================================================

X = df["text"]
y = df["label"]


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

print("\n[4/7] Creating train/test split...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"Training emails: {len(X_train)}")
print(f"Testing emails:  {len(X_test)}")


# ============================================================
# TF-IDF
# ============================================================

print("\n[5/7] Building TF-IDF features...")

vectorizer = TfidfVectorizer(
    lowercase=True,
    strip_accents="unicode",

    # words + short phrases
    ngram_range=(1, 2),

    # Ignore extremely rare terms
    min_df=2,

    # Limit vocabulary
    max_features=30000,

    # Ignore common English words
    sublinear_tf=True
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

print(
    f"TF-IDF training matrix: "
    f"{X_train_tfidf.shape}"
)


# ============================================================
# MODEL
# ============================================================

print("\n[6/7] Training Logistic Regression...")

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    random_state=42
)

model.fit(
    X_train_tfidf,
    y_train
)

print("Model training complete.")


# ============================================================
# EVALUATION
# ============================================================

print("\n[7/7] Evaluating model...")

predictions = model.predict(
    X_test_tfidf
)

probabilities = model.predict_proba(
    X_test_tfidf
)[:, 1]


accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test,
    probabilities
)

cm = confusion_matrix(
    y_test,
    predictions
)

print("\n========================================")
print("MODEL RESULTS")
print("========================================")

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Legitimate",
            "Phishing"
        ],
        zero_division=0
    )
)

print("\nConfusion Matrix:")
print(cm)


# ============================================================
# SAVE MODEL
# ============================================================

model_path = os.path.join(
    MODEL_DIR,
    "email_classifier.pkl"
)

vectorizer_path = os.path.join(
    MODEL_DIR,
    "tfidf_vectorizer.pkl"
)

joblib.dump(
    model,
    model_path
)

joblib.dump(
    vectorizer,
    vectorizer_path
)


# ============================================================
# SAVE METRICS
# ============================================================

metrics = {
    "dataset": DATASET,
    "dataset_size": int(len(df)),

    "train_size": int(len(X_train)),
    "test_size": int(len(X_test)),

    "label_distribution": {
        str(k): int(v)
        for k, v in df["label"]
        .value_counts()
        .to_dict()
        .items()
    },

    "model": "LogisticRegression",

    "vectorizer": {
        "type": "TF-IDF",
        "ngram_range": [1, 2],
        "max_features": 30000,
        "min_df": 2
    },

    "metrics": {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc)
    },

    "confusion_matrix": cm.tolist()
}


metrics_path = os.path.join(
    REPORT_DIR,
    "model_metrics.json"
)

with open(
    metrics_path,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        metrics,
        f,
        indent=4
    )


# ============================================================
# DONE
# ============================================================

print("\n========================================")
print("TRAINING COMPLETE")
print("========================================")

print(f"\nModel:")
print(model_path)

print("\nVectorizer:")
print(vectorizer_path)

print("\nMetrics:")
print(metrics_path)

print("\nMailTrace AI NLP model is ready.")