"""
Training script for NLP-based phishing classification model (TF-IDF + Logistic Regression).
Evaluates using stratified train/test split and reports:
- Accuracy
- Precision
- Recall
- F1 Score
- Confusion Matrix
Persists trained model pipeline and metadata to backend/app/ml/models/.
"""
import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from backend.app.ml.normalizer import TextNormalizer
from backend.app.ml.training.dataset import get_training_corpus

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml_trainer")

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODEL_FILE = MODELS_DIR / "phishing_model.joblib"
METADATA_FILE = MODELS_DIR / "model_metadata.json"


def train_and_evaluate(models_dir: Path = MODELS_DIR) -> Dict[str, Any]:
    """
    Trains TF-IDF + Logistic Regression pipeline, evaluates on stratified test split,
    reports performance metrics, and persists artifacts.
    """
    models_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading training dataset...")
    raw_texts, labels = get_training_corpus()
    logger.info(f"Loaded {len(raw_texts)} total samples ({sum(labels)} phishing, {len(labels) - sum(labels)} legitimate).")

    # Normalize all texts using TextNormalizer
    normalized_texts = [TextNormalizer.normalize(body=t) for t in raw_texts]

    # Stratified Train/Test split (75% train, 25% test)
    X_train, X_test, y_train, y_test = train_test_split(
        normalized_texts,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels
    )
    logger.info(f"Training split: {len(X_train)} samples. Testing split: {len(X_test)} samples.")

    # Build Pipeline: TF-IDF + Logistic Regression
    pipeline = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=5000,
                sublinear_tf=True,
                stop_words="english",
                min_df=1
            )
        ),
        (
            "clf",
            LogisticRegression(
                C=1.5,
                max_iter=1000,
                class_weight="balanced",
                random_state=42,
                solver="liblinear"
            )
        )
    ])

    logger.info("Fitting TF-IDF + Logistic Regression pipeline on training set...")
    pipeline.fit(X_train, y_train)

    # Evaluate on held-out test split
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred, target_names=["legitimate", "phishing"], output_dict=True)

    # Train on full dataset for final deployment artifact
    logger.info("Refitting pipeline on 100% of dataset for deployment artifact...")
    pipeline.fit(normalized_texts, labels)

    # Inspect top indicative features for interpretability
    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["clf"]
    feature_names = vectorizer.get_feature_names_out()
    coefficients = classifier.coef_[0]

    top_phishing_idx = np.argsort(coefficients)[-15:][::-1]
    top_legit_idx = np.argsort(coefficients)[:15]

    top_phishing_features = [
        {"feature": str(feature_names[i]), "weight": float(round(coefficients[i], 4))}
        for i in top_phishing_idx
    ]
    top_legitimate_features = [
        {"feature": str(feature_names[i]), "weight": float(round(coefficients[i], 4))}
        for i in top_legit_idx
    ]

    # Save model binary
    target_model_file = models_dir / "phishing_model.joblib"
    joblib.dump(pipeline, target_model_file)
    logger.info(f"Saved trained model to {target_model_file}")

    # Save metadata JSON
    metadata = {
        "model_type": "TF-IDF + Logistic Regression",
        "version": "1.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(raw_texts),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "evaluation_metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "confusion_matrix": {
                "true_negative": cm[0][0] if len(cm) > 0 and len(cm[0]) > 0 else 0,
                "false_positive": cm[0][1] if len(cm) > 0 and len(cm[0]) > 1 else 0,
                "false_negative": cm[1][0] if len(cm) > 1 and len(cm[1]) > 0 else 0,
                "true_positive": cm[1][1] if len(cm) > 1 and len(cm[1]) > 1 else 0,
                "raw_matrix": cm
            },
            "classification_report": report
        },
        "top_features": {
            "phishing_indicators": top_phishing_features,
            "legitimate_indicators": top_legitimate_features
        }
    }

    target_metadata_file = models_dir / "model_metadata.json"
    with open(target_metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Saved model metadata to {target_metadata_file}")

    # Output formatted report to stdout
    print("\n" + "=" * 60)
    print("      NLP PHISHING CLASSIFIER EVALUATION REPORT")
    print("=" * 60)
    print(f"Model Architecture : TF-IDF + Logistic Regression (Stratified 75/25)")
    print(f"Total Dataset Size : {len(raw_texts)} emails")
    print(f"Accuracy           : {acc:.4f} ({acc*100:.2f}%)")
    print(f"Precision          : {prec:.4f} ({prec*100:.2f}%)")
    print(f"Recall             : {rec:.4f} ({rec*100:.2f}%)")
    print(f"F1 Score           : {f1:.4f} ({f1*100:.2f}%)")
    print("-" * 60)
    print("Confusion Matrix:")
    print(f"  True Negatives (Legitimate classified as Legit) : {cm[0][0]}")
    print(f"  False Positives (Legit classified as Phishing) : {cm[0][1]}")
    print(f"  False Negatives (Phishing classified as Legit) : {cm[1][0]}")
    print(f"  True Positives (Phishing classified as Phishing): {cm[1][1]}")
    print("-" * 60)
    print("Top Phishing Indicative Features:")
    for item in top_phishing_features[:8]:
        print(f"  + {item['feature']:<20} (coeff: {item['weight']:+.4f})")
    print("=" * 60 + "\n")

    return metadata


if __name__ == "__main__":
    train_and_evaluate()
