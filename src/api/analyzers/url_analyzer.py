"""
URL Analyzer — XGBoost-based URL structure analysis.
Inherits from BaseAnalyzer (Inheritance) and encapsulates
model state, threshold, and feature extraction (Encapsulation).
"""
import os
import sys
import logging

import joblib
import pandas as pd

from .base import BaseAnalyzer, AnalysisResult
from ..schemas import ScanRequest

# --- Import feature extraction from sibling package ---
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(os.path.dirname(_CURRENT_DIR))  # src/api/analyzers → src
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)
from features.extract_url_features import extract_features

logger = logging.getLogger(__name__)


class URLAnalyzer(BaseAnalyzer):
    """Analyzes URL structure using XGBoost model (Inheritance + Encapsulation).

    Encapsulates the XGBoost model, optimal threshold, and feature names
    as private state. Inherits the BaseAnalyzer interface.
    """

    def __init__(self):
        self._model = None
        self._threshold: float = 0.5
        self._feature_names: list[str] | None = None

    # --- Abstract property implementations ---

    @property
    def name(self) -> str:
        return "URL"

    @property
    def is_available(self) -> bool:
        return self._model is not None

    # --- Abstract method implementations ---

    def load_model(self, model_dir: str) -> None:
        """Load XGBoost model + optimal threshold from .pkl file."""
        xgb_path = os.path.join(model_dir, "url_xgboost.pkl")
        if os.path.exists(xgb_path):
            model_data = joblib.load(xgb_path)
            self._model = model_data["model"]
            self._threshold = model_data.get("optimal_threshold", 0.5)
            self._feature_names = model_data.get("feature_names", None)
            logger.info(f"XGBoost URL Model Loaded: {xgb_path}")
            logger.info(f"  Optimal Threshold: {self._threshold:.4f}")
            logger.info(f"  Target FPR: < {model_data.get('target_fpr', 'N/A')}")
        else:
            logger.error(f"XGBoost URL Model NOT FOUND at: {xgb_path}")

    def analyze(self, request: ScanRequest) -> AnalysisResult | None:
        """Extract URL features → XGBoost predict_proba → compare threshold.

        Returns None if feature extraction fails.
        """
        features_df = self._extract_features(request.url)
        if features_df is None:
            return None

        # Ensure feature columns match training order
        if self._feature_names:
            features_df = features_df.reindex(columns=self._feature_names, fill_value=0)

        prob = float(self._model.predict_proba(features_df)[0][1])
        is_phishing = prob >= self._threshold

        result = AnalysisResult(
            score=prob,
            threshold=self._threshold,
            is_phishing=is_phishing,
            extra={"url_threshold": self._threshold},
        )

        if is_phishing:
            logger.warning(
                f"[URL-XGB] Phishing detected "
                f"(Score: {prob:.4f} >= threshold {self._threshold:.4f})"
            )
            result.reasons.append({
                "message": f"URL has suspicious structure (Risk score: {prob:.0%})",
                "type": "danger",
            })
        else:
            logger.info(
                f"[URL-XGB] Safe "
                f"(Score: {prob:.4f} < threshold {self._threshold:.4f})"
            )
            result.reasons.append({
                "message": f"URL structure appears normal (Risk score: {prob:.0%})",
                "type": "safe",
            })

        return result

    # --- Private helpers (Encapsulation) ---

    def _extract_features(self, url: str) -> pd.DataFrame | None:
        """Extract URL features using the shared extraction module."""
        try:
            df_input = pd.DataFrame({"url": [str(url).strip()], "label": [0]})
            df_features = extract_features(df_input)
            feature_cols = [c for c in df_features.columns if c not in ("url", "label")]
            return df_features[feature_cols]
        except Exception as e:
            logger.error(f"Error extracting URL features: {e}")
            return None
