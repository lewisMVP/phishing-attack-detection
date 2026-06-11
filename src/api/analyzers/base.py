"""
Abstract Base Class for all analysis modules (Abstraction).

Defines the contract that every analyzer must implement,
enabling polymorphic usage in the prediction pipeline.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..schemas import ScanRequest


@dataclass
class AnalysisResult:
    """Encapsulates the output of any analyzer module (Encapsulation).

    Attributes:
        score:       Phishing probability (0.0–1.0).
        is_phishing: Whether the score exceeds the module's threshold.
        threshold:   The decision threshold used.
        reasons:     Human-readable explanations for the score.
        extra:       Module-specific metadata (thresholds, backend info, etc.).
    """

    score: float = 0.0
    is_phishing: bool = False
    threshold: float = 0.5
    reasons: list[dict[str, str]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


class BaseAnalyzer(ABC):
    """Abstract base class for all analysis modules (Abstraction).

    Subclasses implement concrete analysis logic while exposing
    a uniform interface for the prediction pipeline (Polymorphism).

    Subclasses must implement:
        - name:         Module identifier string (e.g., 'URL', 'TEXT', 'IMAGE')
        - is_available: Whether the model is loaded and ready
        - load_model:   Load model artifacts from disk
        - analyze:      Run analysis on a scan request
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Module identifier (e.g., 'URL', 'TEXT', 'IMAGE')."""
        ...

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Whether this analyzer's model is loaded and ready."""
        ...

    @abstractmethod
    def load_model(self, model_dir: str) -> None:
        """Load model artifacts from the specified directory."""
        ...

    @abstractmethod
    def analyze(self, request: ScanRequest) -> AnalysisResult | None:
        """Run analysis on the request.

        Returns:
            AnalysisResult if analysis was performed, or None if the
            input data was insufficient (e.g., no screenshot for image analysis).
        """
        ...
