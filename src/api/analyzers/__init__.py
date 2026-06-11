"""
Analyzers package — concrete implementations of BaseAnalyzer.

Exports:
    BaseAnalyzer, AnalysisResult (base types)
    URLAnalyzer   — XGBoost URL structure analysis
    TextAnalyzer  — XLM-RoBERTa HTML content analysis
    ImageAnalyzer — YOLO logo detection + brand cross-referencing
"""
from .base import BaseAnalyzer, AnalysisResult
from .url_analyzer import URLAnalyzer
from .text_analyzer import TextAnalyzer
from .image_analyzer import ImageAnalyzer

__all__ = [
    "BaseAnalyzer",
    "AnalysisResult",
    "URLAnalyzer",
    "TextAnalyzer",
    "ImageAnalyzer",
]
