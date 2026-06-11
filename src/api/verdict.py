"""
Verdict Engine — Combines analyzer results into final verdict.
Encapsulates voting logic, suspicious pattern detection, and override rules.
"""
import re
import logging
from urllib.parse import urlparse

from .schemas import ScanResponse, AnalysisDetails, AnalysisReason
from .analyzers.base import AnalysisResult

logger = logging.getLogger(__name__)


class VerdictEngine:
    """Combines all analyzer results into a final verdict (Encapsulation).

    Implements a voting system with critical overrides:
        - total_score >= 2 → PHISHING (multi-model consensus)
        - URL score > 0.90 → PHISHING (critical override)
        - Suspicious patterns + moderate URL score → PHISHING
        - No modules ran → ERROR (fixes silent-fail-to-SAFE bug)
    """

    _SUSPICIOUS_TLDS = frozenset({
        ".cfd", ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".pw", ".cc", ".su", ".buzz", ".rest", ".icu", ".cam", ".info",
    })

    _BRAND_KEYWORDS = [
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "bank", "paypal", "microsoft", "apple", "amazon",
        "netflix", "support", "service", "billing", "invoice",
    ]

    def compute_verdict(
        self,
        url: str,
        results: dict[str, AnalysisResult],
    ) -> ScanResponse:
        """Combine all analyzer results into a final verdict.

        Args:
            url:     The URL being analyzed.
            results: Mapping of analyzer name → AnalysisResult
                     (only contains analyzers that actually ran).

        Returns:
            ScanResponse with verdict, confidence, and detailed breakdown.
        """
        reasons: list[dict[str, str]] = []
        modules_run: list[str] = list(results.keys())

        # --- FIX: If no modules ran, return ERROR instead of SAFE ---
        if not modules_run:
            logger.error("No analysis modules ran — returning ERROR verdict")
            return ScanResponse(
                url=url,
                final_verdict="ERROR",
                confidence=0.0,
                details=AnalysisDetails(
                    modules_run=[],
                    reasons=[AnalysisReason(
                        message="Unable to analyze — no models available",
                        type="danger",
                    )],
                ),
            )

        # --- Protocol check (informational only, does NOT affect scoring) ---
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        if parsed_url.scheme != "https":
            logger.warning(f"[PROTOCOL] Site does not use HTTPS ({parsed_url.scheme}://)")
            reasons.append({
                "message": "This site does not use HTTPS encryption. "
                           "Data sent to this site may not be secure.",
                "type": "warning",
            })
        else:
            reasons.append({"message": "Site uses HTTPS encryption", "type": "safe"})

        # --- Accumulate risk score from analyzers ---
        total_score = 0
        url_prob = 0.0

        url_result = results.get("URL")
        if url_result:
            url_prob = url_result.score
            if url_result.is_phishing:
                total_score += 1
            reasons.extend(url_result.reasons)

        text_result = results.get("TEXT")
        if text_result:
            if text_result.is_phishing:
                total_score += 1
            reasons.extend(text_result.reasons)

        image_result = results.get("IMAGE")
        if image_result:
            if image_result.is_phishing:
                total_score += 1
            reasons.extend(image_result.reasons)

        logger.info(f"[SCORING] Total Risk Points: {total_score}/3")

        # --- Suspicious pattern detection (heuristic) ---
        pattern_reasons = self._check_suspicious_patterns(domain)
        reasons.extend(pattern_reasons)

        has_suspicious_tld = any(domain.endswith(tld) for tld in self._SUSPICIOUS_TLDS)
        has_random_subdomain = bool(re.search(r"[a-z0-9]{10,}\.", domain))

        domain_without_www = domain.replace("www.", "")
        domain_parts = domain_without_www.split(".")
        main_domain = domain_parts[0] if len(domain_parts) > 0 else ""
        has_suspicious_hyphen = "-" in main_domain and len(main_domain) > 5

        # --- Final verdict logic (preserved exactly from original) ---
        verdict, confidence = self._compute_final_verdict(
            total_score=total_score,
            url_prob=url_prob,
            has_suspicious_tld=has_suspicious_tld,
            has_random_subdomain=has_random_subdomain,
            has_suspicious_hyphen=has_suspicious_hyphen,
            reasons=reasons,
        )

        # --- Build response ---
        details = AnalysisDetails(
            url_score=url_result.score if url_result else 0.0,
            url_threshold=url_result.extra.get("url_threshold") if url_result else None,
            text_score=text_result.score if text_result else 0.0,
            text_threshold=text_result.extra.get("text_threshold") if text_result else None,
            text_backend=text_result.extra.get("text_backend") if text_result else None,
            logo_detected=(
                image_result.extra.get("logo_detected", []) if image_result else []
            ),
            logo_mismatch=(
                image_result.extra.get("logo_mismatch", False) if image_result else False
            ),
            modules_run=modules_run,
            reasons=[
                AnalysisReason(message=r["message"], type=r["type"]) for r in reasons
            ],
        )

        response = ScanResponse(
            url=url,
            final_verdict=verdict,
            confidence=confidence,
            details=details,
        )

        logger.info(f"[RESULT] Verdict: {verdict} | Confidence: {confidence}")
        return response

    # --- Private helpers (Encapsulation) ---

    def _check_suspicious_patterns(self, domain: str) -> list[dict[str, str]]:
        """Detect suspicious URL patterns and return informational reasons."""
        reasons: list[dict[str, str]] = []

        # Suspicious TLD
        has_suspicious_tld = any(domain.endswith(tld) for tld in self._SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            tld_match = [tld for tld in self._SUSPICIOUS_TLDS if domain.endswith(tld)]
            reasons.append({
                "message": f"Uses suspicious domain extension "
                           f"({tld_match[0] if tld_match else 'unknown'})",
                "type": "danger",
            })

        # Random-looking subdomain
        if re.search(r"[a-z0-9]{10,}\.", domain):
            reasons.append({
                "message": "URL contains random-looking subdomain pattern",
                "type": "danger",
            })

        # Suspicious hyphenation
        domain_without_www = domain.replace("www.", "")
        domain_parts = domain_without_www.split(".")
        main_domain = domain_parts[0] if len(domain_parts) > 0 else ""
        if "-" in main_domain and len(main_domain) > 5:
            reasons.append({
                "message": f"Domain uses suspicious hyphenation ({main_domain})",
                "type": "danger",
            })

        # Brand/action keywords in domain
        has_brand_keyword = any(kw in domain.lower() for kw in self._BRAND_KEYWORDS)
        if has_brand_keyword:
            matched_kw = [kw for kw in self._BRAND_KEYWORDS if kw in domain.lower()]
            reasons.append({
                "message": f"Domain contains brand/action keywords: {', '.join(matched_kw)}",
                "type": "danger",
            })

        return reasons

    def _compute_final_verdict(
        self,
        total_score: int,
        url_prob: float,
        has_suspicious_tld: bool,
        has_random_subdomain: bool,
        has_suspicious_hyphen: bool,
        reasons: list[dict[str, str]],
    ) -> tuple[str, float]:
        """Apply voting + override rules to determine verdict and confidence.

        Logic preserved exactly from original implementation:
        1. total_score >= 2 → PHISHING (consensus)
        2. url_prob > 0.90 → PHISHING (critical override)
        3. Suspicious TLD + url_prob > 0.6 → PHISHING
        4. Suspicious hyphen + url_prob > 0.6 → PHISHING
        5. Random subdomain + url_prob > 0.5 → PHISHING
        6. Otherwise → SAFE
        """
        if total_score >= 2:
            return "PHISHING", 0.95

        if url_prob > 0.90:
            logger.info(
                f"[CRITICAL] Very High URL Risk Score ({url_prob:.4f}). Override to PHISHING."
            )
            reasons.append({
                "message": f"Extremely high URL risk score ({url_prob:.0%})",
                "type": "danger",
            })
            return "PHISHING", 0.90

        if has_suspicious_tld and url_prob > 0.6:
            logger.info(
                "[CRITICAL] Suspicious TLD detected with moderate risk. Override to PHISHING."
            )
            return "PHISHING", 0.85

        if has_suspicious_hyphen and url_prob > 0.6:
            logger.info(
                "[CRITICAL] Suspicious hyphenated domain detected. Override to PHISHING."
            )
            return "PHISHING", 0.80

        if has_random_subdomain and url_prob > 0.5:
            logger.info(
                "[CRITICAL] Random subdomain pattern detected. Override to PHISHING."
            )
            return "PHISHING", 0.85

        # SAFE verdict
        confidence = 0.45 if total_score == 1 else 0.9
        if total_score == 0:
            reasons.append({
                "message": "No threats detected across all analysis modules",
                "type": "safe",
            })
        return "SAFE", confidence
