"""
Image Analyzer — YOLO-based logo detection with brand cross-referencing.
Inherits from BaseAnalyzer (Inheritance) and uses BrandDomainConfig
via dependency injection (Encapsulation).
"""
import base64
import io
import os
import logging
from urllib.parse import urlparse

from PIL import Image
from ultralytics import YOLO

from .base import BaseAnalyzer, AnalysisResult
from ..schemas import ScanRequest
from ..config import BrandDomainConfig

logger = logging.getLogger(__name__)


class ImageAnalyzer(BaseAnalyzer):
    """Detects brand logos via YOLO and cross-references with URL domain.

    Inherits BaseAnalyzer interface (Inheritance) and encapsulates
    YOLO model + brand config as private state (Encapsulation).
    BrandDomainConfig is injected via constructor (Dependency Injection).
    """

    _CONFIDENCE_THRESHOLD = 0.45
    _TARGET_WIDTH = 640
    _MAX_HEIGHT = 640
    _MIN_SCREENSHOT_LENGTH = 100

    def __init__(self, brand_config: BrandDomainConfig):
        self._model = None
        self._brand_config = brand_config  # Dependency injection

    # --- Abstract property implementations ---

    @property
    def name(self) -> str:
        return "IMAGE"

    @property
    def is_available(self) -> bool:
        return self._model is not None

    # --- Abstract method implementations ---

    def load_model(self, model_dir: str) -> None:
        """Load YOLO logo detection model."""
        yolo_path = os.path.join(model_dir, "yolo26n_logo_detector.pt")
        if os.path.exists(yolo_path):
            self._model = YOLO(yolo_path)
            logger.info(f"[CV Model] YOLO26 Loaded: {yolo_path}")
        else:
            logger.error(f"[CV Model] NOT FOUND at: {yolo_path}")

    def analyze(self, request: ScanRequest) -> AnalysisResult | None:
        """Detect logos in screenshot → cross-reference with URL domain.

        Returns None if screenshot data is too short or missing.
        """
        if len(request.screenshot_base64) <= self._MIN_SCREENSHOT_LENGTH:
            return None

        image = self._decode_image(request.screenshot_base64)
        image = self._preprocess_image(image)
        detected_logos = self._detect_logos(image)

        result = AnalysisResult(
            extra={"logo_detected": detected_logos, "logo_mismatch": False},
        )

        if detected_logos:
            parsed_uri = urlparse(request.url)
            current_domain = parsed_uri.netloc.lower()
            html_content = request.html_content or ""

            mismatched_brands, reasons = self._cross_reference_logos(
                detected_logos, current_domain, html_content
            )

            if mismatched_brands:
                result.extra["logo_mismatch"] = True
                result.is_phishing = True
                result.score = 1.0

            result.reasons.extend(reasons)
        else:
            logger.info("[YOLO] No brand logo detected in screenshot")
            result.reasons.append({
                "message": "No brand logo detected in screenshot",
                "type": "safe",
            })

        return result

    # --- Private helpers (Encapsulation) ---

    def _decode_image(self, screenshot_base64: str) -> Image.Image:
        """Decode base64 screenshot to PIL Image with format validation."""
        img_str = screenshot_base64
        if "," in img_str:
            img_str = img_str.split(",")[1]

        image_data = base64.b64decode(img_str)
        image = Image.open(io.BytesIO(image_data))

        # Validate image format to prevent Pillow CVE exploits
        if image.format and image.format.upper() not in ("PNG", "JPEG", "WEBP", "JPG"):
            raise ValueError(f"Unsupported image format: {image.format}")

        return image

    def _preprocess_image(self, image: Image.Image) -> Image.Image:
        """Resize and crop to match YOLO training data format (640×640)."""
        width, height = image.size

        # Resize to training width, preserving aspect ratio
        if width != self._TARGET_WIDTH:
            new_height = int(height * (self._TARGET_WIDTH / width))
            image = image.resize((self._TARGET_WIDTH, new_height), Image.LANCZOS)
            logger.debug(f"Resized to match training format: {image.size}")

        # Crop overly tall images (long scrolling pages) to header region
        if image.size[1] > self._MAX_HEIGHT:
            image = image.crop((0, 0, self._TARGET_WIDTH, self._MAX_HEIGHT))
            logger.debug(f"Cropped height to: {image.size}")

        return image

    def _detect_logos(self, image: Image.Image) -> list[str]:
        """Run YOLO inference and return unique detected brand names."""
        results = self._model(
            image,
            conf=self._CONFIDENCE_THRESHOLD,
            imgsz=self._TARGET_WIDTH,
            verbose=False,
        )

        logger.debug(f"YOLO detections count: {len(results[0].boxes)}")

        detected_logos = []
        for result in results:
            for box in result.boxes:
                cls_id = int(box.cls[0])
                conf = float(box.conf[0])
                class_name = self._model.names[cls_id]
                logger.debug(f"YOLO Raw Detection: {class_name} ({conf:.2f})")
                # FIX: Removed redundant conf >= 0.45 check (already filtered by YOLO)
                detected_logos.append(class_name)

        return list(set(detected_logos))

    def _cross_reference_logos(
        self,
        detected_logos: list[str],
        domain: str,
        html_content: str,
    ) -> tuple[list[str], list[dict[str, str]]]:
        """Cross-reference detected logos with URL domain and HTML content.

        Returns:
            Tuple of (mismatched_brands, reasons).
        """
        reasons: list[dict[str, str]] = []
        mismatched_brands: list[str] = []

        for brand in detected_logos:
            domain_match_status = self._brand_config.check_domain_match(brand, domain)
            content_match = self._brand_config.check_content_match(brand, html_content)

            if domain_match_status == "MATCH":
                logger.info(
                    f"[YOLO] {brand} logo detected — URL matches ({domain})"
                )
            elif domain_match_status == "MISMATCH":
                if content_match:
                    logger.warning(
                        f"[YOLO] {brand} logo + content match but URL doesn't match → suspicious"
                    )
                else:
                    logger.warning(
                        f"[YOLO] {brand} logo detected but URL ({domain}) doesn't match → suspicious"
                    )
                mismatched_brands.append(brand)
            elif domain_match_status == "UNKNOWN":
                logger.info(
                    f"[YOLO] {brand} logo detected (brand domain unknown, skipping URL cross-reference)"
                )

        # Build human-readable reasons
        if mismatched_brands:
            brand_list = ", ".join([b.capitalize() for b in mismatched_brands])
            reasons.append({
                "message": f"{brand_list} logo detected but URL is not an official {brand_list} domain",
                "type": "danger",
            })
        else:
            matched_brands = [
                b for b in detected_logos
                if self._brand_config.check_domain_match(b, domain) == "MATCH"
            ]
            if matched_brands:
                brand_list = ", ".join([b.capitalize() for b in matched_brands])
                reasons.append({
                    "message": f"{brand_list} logo detected and matches the website domain",
                    "type": "safe",
                })
                logger.info("[YOLO] All detected logos match the domain — no penalty")
            else:
                brand_list = ", ".join([b.capitalize() for b in detected_logos])
                reasons.append({
                    "message": f"{brand_list} logo detected (brand domain unknown)",
                    "type": "safe",
                })
                logger.info("[YOLO] Detected logos have unknown domains — no penalty")

        return mismatched_brands, reasons
