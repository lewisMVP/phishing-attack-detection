"""
Configuration classes for the Phishing Detection API.
Encapsulates whitelist logic and brand-domain mapping (Encapsulation).
"""
import logging

logger = logging.getLogger(__name__)


class WhitelistConfig:
    """Encapsulates trusted domain whitelist and lookup logic (Encapsulation).

    The whitelist bypasses AI analysis for known legitimate domains.
    Subdomain matching is supported (e.g., mail.google.com matches google.com).
    """

    TRUSTED_DOMAINS: set[str] = {
        # Global Tech Giants
        "google.com",
        "google",       # .google gTLD is owned by Google
        "microsoft.com",
        "facebook.com",
        "youtube.com",
        "github.com",
        "amazon.com",
        "stackoverflow.com",
        "chatgpt.com",
        "openai.com",
        "claude.ai",
        "perplexity.ai",
        "apple.com",
        "netflix.com",
        "linkedin.com",
        "twitter.com",
        "x.com",
        "instagram.com",
        "reddit.com",
        "wikipedia.org",
        "discord.com",
        "spotify.com",
        "zoom.us",
        "dropbox.com",
        "pepsi.com",
        "starbucks.com",          # FIX: was missing comma → string concatenation bug
        "coca-colacompany.com",   # FIX: was missing comma
        "adidas.com",             # FIX: was missing comma
        "nike.com",               # FIX: was missing comma

        # Vietnamese trusted sites
        "vnexpress.net",
        "tuoitre.vn",
        "thanhnien.vn",
        "dantri.com.vn",
        "vietnamnet.vn",
        "shopee.vn",
        "tiki.vn",
        "lazada.vn",
        "sendo.vn",
        "momo.vn",
        "vnpay.vn",
        "zalopay.vn",
        "vietcombank.com.vn",
        "techcombank.com.vn",
        "vietinbank.vn",
        "bidv.com.vn",
        "fpt.com.vn",
        "viettel.vn",
        "vingroup.net",
    }

    def is_whitelisted(self, domain: str) -> bool:
        """Check if domain or its parent domain is in the whitelist."""
        domain = domain.lower()
        # Exact match
        if domain in self.TRUSTED_DOMAINS:
            return True
        # Subdomain match (e.g., mail.google.com → google.com)
        for trusted in self.TRUSTED_DOMAINS:
            if domain.endswith("." + trusted):
                return True
        return False


class BrandDomainConfig:
    """Encapsulates brand-domain mapping and cross-referencing logic (Encapsulation).

    Used by ImageAnalyzer to verify that detected brand logos match
    the actual website domain, catching impersonation attempts.
    """

    BRAND_MAP: dict[str, list[str]] = {
        # Tech
        "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com",
                       "azure.com", "bing.com", "msn.com"],
        "google":    ["google.com", "google.co", "googleapis.com", "gstatic.com",
                      "youtube.com", "gmail.com", "antigravity.google"],
        "apple":     ["apple.com", "icloud.com", "itunes.com"],
        "adobe":     ["adobe.com", "adobelogin.com"],
        "facebook":  ["facebook.com", "fb.com", "meta.com", "messenger.com"],
        "linkedin":  ["linkedin.com"],
        "amazon":    ["amazon.com", "amazon.co", "aws.amazon.com",
                      "amazonservices.com"],
        "netflix":   ["netflix.com"],
        "tiktok":    ["tiktok.com"],
        "instagram": ["instagram.com"],

        # E-commerce / Shipping
        "ebay":   ["ebay.com"],
        "shopee": ["shopee.com", "shopee.vn", "shopee.co.id", "shopee.ph",
                   "shopee.com.my", "shopee.sg", "shopee.co.th", "shopee.tw"],
        "lazada": ["lazada.com", "lazada.vn", "lazada.co.id", "lazada.com.ph",
                   "lazada.com.my", "lazada.sg", "lazada.co.th"],
        "tiki":   ["tiki.vn"],
        "dhl":    ["dhl.com"],
        "fedex":  ["fedex.com"],
        "ups":    ["ups.com"],

        # International Finance / Payments
        "paypal":        ["paypal.com"],
        "stripe":        ["stripe.com"],
        "hsbc":          ["hsbc.com", "hsbc.co.uk", "hsbc.com.vn"],
        "citibank":      ["citibank.com", "citi.com"],
        "bankofamerica": ["bankofamerica.com", "bofa.com"],
        "chase":         ["chase.com"],
        "visa":          ["visa.com"],
        "mastercard":    ["mastercard.com", "mastercard.us"],

        # Vietnamese Finance / Payments
        "momo":       ["momo.vn"],
        "vnpay":      ["vnpay.vn"],
        "zalopay":    ["zalopay.vn"],
        "vietcombank": ["vietcombank.com.vn", "vietcombank.com"],
        "techcombank": ["techcombank.com.vn", "techcombank.com"],
        "mbbank":     ["mbbank.com.vn", "mb.com.vn"],
        "bidv":       ["bidv.com.vn"],
    }

    def check_domain_match(self, brand: str, domain: str) -> str:
        """Check if detected brand matches the website domain.

        Returns:
            'MATCH'    — brand's legitimate domain matches the URL
            'MISMATCH' — brand is known but domain doesn't match
            'UNKNOWN'  — brand not in mapping, can't cross-reference
        """
        brand_lower = brand.lower()
        domain_lower = domain.lower()
        if brand_lower not in self.BRAND_MAP:
            return "UNKNOWN"
        for legit_domain in self.BRAND_MAP[brand_lower]:
            if domain_lower == legit_domain or domain_lower.endswith("." + legit_domain):
                return "MATCH"
        return "MISMATCH"

    def check_content_match(self, brand: str, html_content: str) -> bool:
        """Check if detected brand name appears in page HTML content."""
        if not html_content:
            return False
        return brand.lower() in html_content.lower()
