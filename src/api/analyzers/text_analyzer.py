"""
Text Analyzer — XLM-RoBERTa-based HTML content analysis.
Demonstrates Polymorphism through BaseInferenceBackend with
ONNX and PyTorch implementations, and Inheritance from BaseAnalyzer.
"""
import os
import json
import logging
from abc import ABC, abstractmethod

import numpy as np
from transformers import AutoTokenizer
from scipy.special import softmax as scipy_softmax

from .base import BaseAnalyzer, AnalysisResult
from ..schemas import ScanRequest

logger = logging.getLogger(__name__)


# =============================================================================
# Inference Backend Hierarchy (Polymorphism)
# =============================================================================

class BaseInferenceBackend(ABC):
    """Abstract inference backend (Abstraction + Polymorphism).

    Allows TextAnalyzer to use ONNX or PyTorch transparently —
    the caller doesn't need to know which backend is active.
    """

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Backend identifier (e.g., 'onnx', 'pytorch')."""
        ...

    @abstractmethod
    def predict(self, text: str, tokenizer) -> float:
        """Run inference and return phishing probability (0.0–1.0)."""
        ...


class OnnxBackend(BaseInferenceBackend):
    """ONNX Runtime inference — fast, small memory footprint (Inheritance)."""

    def __init__(self, session):
        self._session = session

    @property
    def backend_name(self) -> str:
        return "onnx"

    def predict(self, text: str, tokenizer) -> float:
        encoded = tokenizer(
            text,
            truncation=True,
            max_length=256,
            padding=True,
            return_tensors="np",
        )
        ort_inputs = {
            "input_ids": encoded["input_ids"].astype(np.int64),
            "attention_mask": encoded["attention_mask"].astype(np.int64),
        }
        logits = self._session.run(None, ort_inputs)[0]
        probs = scipy_softmax(logits, axis=-1)
        return float(probs[0][1])


class PyTorchBackend(BaseInferenceBackend):
    """PyTorch inference — fallback when ONNX is unavailable (Inheritance)."""

    def __init__(self, model):
        self._model = model

    @property
    def backend_name(self) -> str:
        return "pytorch"

    def predict(self, text: str, tokenizer) -> float:
        import torch

        inputs = tokenizer(
            text, return_tensors="pt", truncation=True, max_length=256
        )
        with torch.no_grad():
            outputs = self._model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        return probs[0][1].item()


# =============================================================================
# TextAnalyzer (Inheritance + Polymorphism)
# =============================================================================

class TextAnalyzer(BaseAnalyzer):
    """Analyzes page HTML content using XLM-RoBERTa (Inheritance).

    Uses BaseInferenceBackend polymorphism to transparently switch
    between ONNX and PyTorch inference backends.
    """

    _MIN_HTML_LENGTH = 50  # Minimum HTML length to run analysis

    def __init__(self):
        self._backend: BaseInferenceBackend | None = None
        self._tokenizer = None
        self._threshold: float = 0.5

    # --- Abstract property implementations ---

    @property
    def name(self) -> str:
        return "TEXT"

    @property
    def is_available(self) -> bool:
        return self._backend is not None and self._tokenizer is not None

    # --- Abstract method implementations ---

    def load_model(self, model_dir: str) -> None:
        """Load NLP model: try ONNX first, fallback to PyTorch.

        The backend is selected via polymorphism — TextAnalyzer doesn't
        need to know which backend is active after loading.
        """
        onnx_path = os.path.join(model_dir, "xlmr_phishing_onnx")
        pytorch_path = os.path.join(model_dir, "xlmr_phishing")

        loaded = False

        # Try ONNX first (faster, smaller memory)
        if os.path.exists(onnx_path):
            try:
                loaded = self._load_onnx(onnx_path)
            except Exception as e:
                logger.warning(
                    f"[NLP Model] ONNX load failed: {e}. Trying PyTorch fallback..."
                )

        # Fallback to PyTorch
        if not loaded and os.path.exists(pytorch_path):
            try:
                loaded = self._load_pytorch(pytorch_path)
            except Exception as e:
                logger.error(f"[NLP Model] PyTorch load failed: {e}")

        if not loaded:
            logger.error(
                f"[NLP Model] NOT FOUND at: {onnx_path} or {pytorch_path}"
            )
            return

        # Load optimized threshold from summary.json
        self._load_threshold(onnx_path, pytorch_path)

    def analyze(self, request: ScanRequest) -> AnalysisResult | None:
        """Analyze HTML content for phishing patterns.

        Returns None if html_content is too short to analyze.
        Uses self._backend.predict() — polymorphic (ONNX or PyTorch).
        """
        if len(request.html_content) <= self._MIN_HTML_LENGTH:
            return None

        # Polymorphism: backend.predict() — doesn't matter if ONNX or PyTorch
        phishing_prob = self._backend.predict(request.html_content, self._tokenizer)
        is_phishing = phishing_prob >= self._threshold

        result = AnalysisResult(
            score=phishing_prob,
            threshold=self._threshold,
            is_phishing=is_phishing,
            extra={
                "text_threshold": self._threshold,
                "text_backend": self._backend.backend_name,
            },
        )

        if is_phishing:
            logger.warning(
                f"[XLM-R/{self._backend.backend_name}] Phishing Content Detected "
                f"(Score: {phishing_prob:.4f} >= threshold {self._threshold:.4f})"
            )
            result.reasons.append({
                "message": f"Page content contains phishing patterns (Score: {phishing_prob:.0%})",
                "type": "danger",
            })
        else:
            logger.info(
                f"[XLM-R/{self._backend.backend_name}] Safe "
                f"(Score: {phishing_prob:.4f} < threshold {self._threshold:.4f})"
            )
            result.reasons.append({
                "message": f"Page content appears legitimate (Score: {phishing_prob:.0%})",
                "type": "safe",
            })

        return result

    # --- Private helpers (Encapsulation) ---

    def _load_onnx(self, onnx_path: str) -> bool:
        """Load ONNX Runtime session and create OnnxBackend."""
        import onnxruntime as ort

        quantized_model = os.path.join(onnx_path, "model_quantized.onnx")
        float_model = os.path.join(onnx_path, "model.onnx")

        if os.path.exists(quantized_model):
            onnx_file = quantized_model
            model_type = "ONNX INT8 Quantized"
        elif os.path.exists(float_model):
            onnx_file = float_model
            model_type = "ONNX Float32"
        else:
            raise FileNotFoundError("No .onnx model file found")

        sess_options = ort.SessionOptions()
        sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        sess_options.intra_op_num_threads = 4

        session = ort.InferenceSession(onnx_file, sess_options)
        self._tokenizer = AutoTokenizer.from_pretrained(onnx_path, fix_mistral_regex=True)
        self._backend = OnnxBackend(session)  # Polymorphism: assign concrete backend

        size_mb = os.path.getsize(onnx_file) / (1024 ** 2)
        logger.info(f"[NLP Model] {model_type} Loaded: {onnx_file} ({size_mb:.0f} MB)")
        return True

    def _load_pytorch(self, pytorch_path: str) -> bool:
        """Load PyTorch model and create PyTorchBackend."""
        from transformers import AutoModelForSequenceClassification

        self._tokenizer = AutoTokenizer.from_pretrained(pytorch_path, fix_mistral_regex=True)
        model = AutoModelForSequenceClassification.from_pretrained(pytorch_path)
        self._backend = PyTorchBackend(model)  # Polymorphism: assign concrete backend

        safetensors_path = os.path.join(pytorch_path, "model.safetensors")
        if os.path.exists(safetensors_path):
            size_mb = os.path.getsize(safetensors_path) / (1024 ** 2)
            logger.info(
                f"[NLP Model] PyTorch XLM-RoBERTa Loaded: {pytorch_path} ({size_mb:.0f} MB)"
            )
        else:
            logger.info(f"[NLP Model] PyTorch XLM-RoBERTa Loaded: {pytorch_path}")
        return True

    def _load_threshold(self, onnx_path: str, pytorch_path: str) -> None:
        """Load optimized threshold from summary.json (check both model dirs)."""
        for model_path in [onnx_path, pytorch_path]:
            summary_path = os.path.join(model_path, "summary.json")
            if os.path.exists(summary_path):
                with open(summary_path, "r", encoding="utf-8") as f:
                    summary = json.load(f)
                self._threshold = summary.get("optimized_threshold", 0.5)
                logger.info(f"  Optimized Threshold: {self._threshold:.4f}")
                logger.info(f"  Test Metrics: {summary.get('test_metrics', 'N/A')}")
                return
        logger.warning(
            f"summary.json not found — using default threshold {self._threshold}"
        )
