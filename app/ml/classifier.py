"""
Runtime inference service for NLP-based phishing classification.
Loads pre-trained TF-IDF + Logistic Regression model from disk without retraining.
Handles edge cases (empty text, non-English unicode, missing model) gracefully.
"""
import os
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

from backend.app.ml.normalizer import TextNormalizer

logger = logging.getLogger("phishing_classifier")


class PhishingClassifier:
    """
    Interpretable baseline phishing classifier (TF-IDF + Logistic Regression).
    Predicts phishing probability from email subject and plain-text body.
    """

    DEFAULT_MODEL_DIR = Path(__file__).resolve().parent / "models"
    DEFAULT_MODEL_PATH = DEFAULT_MODEL_DIR / "phishing_model.joblib"
    DEFAULT_METADATA_PATH = DEFAULT_MODEL_DIR / "model_metadata.json"

    def __init__(self, model_path: Optional[str | Path] = None, metadata_path: Optional[str | Path] = None):
        self.model_path = Path(model_path) if model_path else self.DEFAULT_MODEL_PATH
        self.metadata_path = Path(metadata_path) if metadata_path else self.DEFAULT_METADATA_PATH
        self.pipeline = None
        self.metadata = {}
        self._load_model()

    def _load_model(self):
        """Loads pre-trained pipeline and metadata from disk without retraining."""
        if not self.model_path.exists():
            logger.warning(f"Phishing ML model artifact not found at {self.model_path}. Inference disabled.")
            self.pipeline = None
            return

        try:
            import joblib
            self.pipeline = joblib.load(self.model_path)
            logger.info(f"Loaded ML phishing model successfully from {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load ML model artifact from {self.model_path}: {e}")
            self.pipeline = None

        if self.metadata_path.exists():
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load ML metadata from {self.metadata_path}: {e}")

    @property
    def is_available(self) -> bool:
        """Returns True if the ML model is loaded and ready for inference."""
        return self.pipeline is not None

    def predict(self, subject: Optional[str] = None, body: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes NLP phishing classification pipeline:
        subject + body -> normalization -> TF-IDF -> Logistic Regression -> probability.

        Returns structured dict matching MLAssessmentResult schema.
        Never raises an unhandled exception if input is malformed or model is missing.
        """
        # Normalization
        try:
            normalized_text = TextNormalizer.normalize(subject=subject, body=body)
        except Exception as e:
            logger.warning(f"Text normalization encountered unexpected error: {e}")
            normalized_text = ""

        # Empty body & subject edge case
        if not normalized_text:
            return {
                "classification": "legitimate",
                "probability": 0.0,
                "confidence": "low",
                "available": self.is_available,
                "top_features": [],
                "model_name": "TF-IDF + Logistic Regression",
                "notice": "Empty or whitespace-only email text analyzed"
            }

        # Failure mode: Model unavailable
        if self.pipeline is None:
            return {
                "classification": "unknown",
                "probability": None,
                "confidence": "none",
                "available": False,
                "top_features": [],
                "model_name": "TF-IDF + Logistic Regression",
                "notice": "ML model artifact unavailable; forensic scoring continues"
            }

        try:
            # Predict probabilities
            probabilities = self.pipeline.predict_proba([normalized_text])[0]
            phishing_prob = float(probabilities[1])
            phishing_prob = max(0.0, min(1.0, phishing_prob))

            classification = "phishing" if phishing_prob >= 0.5 else "legitimate"

            # Derive confidence label based on distance from decision boundary (0.5)
            distance = abs(phishing_prob - 0.5)
            if distance >= 0.30:
                confidence = "high"
            elif distance >= 0.15:
                confidence = "medium"
            else:
                confidence = "low"

            # Extract top matching indicative tokens present in normalized text
            top_features = self._extract_matching_features(normalized_text)

            return {
                "classification": classification,
                "probability": round(phishing_prob, 4),
                "confidence": confidence,
                "available": True,
                "top_features": top_features,
                "model_name": "TF-IDF + Logistic Regression"
            }

        except Exception as e:
            logger.error(f"Inference error during ML classification: {e}")
            return {
                "classification": "unknown",
                "probability": None,
                "confidence": "none",
                "available": False,
                "top_features": [],
                "model_name": "TF-IDF + Logistic Regression",
                "notice": f"Inference exception: {str(e)}"
            }

    def _extract_matching_features(self, text: str, max_tokens: int = 5) -> List[str]:
        """Extracts top phishing or legitimate features that actually appear in the text."""
        matched: List[str] = []
        try:
            vectorizer = self.pipeline.named_steps.get("tfidf")
            classifier = self.pipeline.named_steps.get("clf")
            if not vectorizer or not classifier:
                return matched

            # Look up feature names and coefficients
            feature_names = vectorizer.get_feature_names_out()
            coeffs = classifier.coef_[0]

            # Transform single text to get active non-zero TF-IDF vocabulary indices
            tfidf_vec = vectorizer.transform([text])
            _, col_indices = tfidf_vec.nonzero()

            # Rank active features by absolute coefficient magnitude
            active_features = [
                (feature_names[idx], coeffs[idx])
                for idx in col_indices
                if idx < len(feature_names)
            ]

            # Prefer features that contributed in the direction of the prediction (positive for phishing)
            active_features.sort(key=lambda x: x[1], reverse=True)
            matched = [feat for feat, weight in active_features[:max_tokens]]
        except Exception:
            pass

        return matched


global_phishing_classifier = PhishingClassifier()
