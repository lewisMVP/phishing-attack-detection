"""
Advanced URL Feature Extraction for XGBoost Phishing Detection
==============================================================
Extracts 80+ features from URLs optimized for minimizing False Positive Rate.

Features are grouped into 9 categories:
  1. Length-based features
  2. Count-based features
  3. Domain analysis (entropy, subdomain depth, TLD-in-path)
  4. Keyword detection (split by domain vs path for FPR reduction)
  5. Protocol & structure features
  6. Ratio-based features
  7. Shortening service detection
  8. TLD reputation scoring (NEW)
  9. Domain linguistic analysis (NEW)

Performance: Uses vectorized Pandas operations + .apply() instead of iterrows().
Robustness: Handles missing schemes, unicode, malformed URLs gracefully.
"""
import pandas as pd
import numpy as np
from urllib.parse import urlparse, parse_qs
import re
import os
import ipaddress
import math
from collections import Counter
import time

import tldextract


# --- CONFIGURATION ---
PHISHING_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'processed', 'phishing_urls.csv')
BENIGN_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'processed', 'benign_urls.csv')
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'datasets', 'url_features_dataset.csv')

# Known URL shortening services
SHORTENING_SERVICES = frozenset([
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy', 'shorturl.at',
    'tiny.cc', 'x.co', 'shorte.st', 'go2l.ink', 'tr.im', 'cli.gs',
    'v.gd', 'qr.ae', 'u.to', 'lnkd.in', 'db.tt', 'j.mp',
])

# Suspicious keywords - checked separately in domain vs path
SUSPICIOUS_KEYWORDS = [
    'login', 'secure', 'account', 'verify', 'signin', 'bank',
    'confirm', 'update', 'password', 'credential', 'suspend',
    'expire', 'wallet', 'paypal', 'netflix', 'apple', 'microsoft',
]

# Common TLDs to detect in path
COMMON_TLDS = frozenset([
    '.com', '.net', '.org', '.info', '.biz', '.ru', '.cn', '.tk',
    '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.online', '.site',
])

# TLD reputation tiers (higher = more suspicious)
# Score 0 = highly trusted, 1 = normal, 2 = somewhat suspicious, 3 = very suspicious
_TLD_REPUTATION = {
    # Tier 0: Highly trusted (government, education, established)
    'gov': 0, 'edu': 0, 'mil': 0, 'int': 0,
    'gov.uk': 0, 'gov.au': 0, 'gov.vn': 0, 'edu.vn': 0,
    'ac.uk': 0, 'ac.jp': 0, 'go.jp': 0,
    # Tier 1: Normal / well-established commercial
    'com': 1, 'org': 1, 'net': 1, 'co': 1, 'io': 1, 'dev': 1, 'app': 1,
    'com.vn': 1, 'vn': 1, 'com.au': 1, 'co.uk': 1, 'co.jp': 1,
    'de': 1, 'fr': 1, 'jp': 1, 'kr': 1, 'uk': 1, 'us': 1, 'ca': 1,
    'eu': 1, 'nl': 1, 'se': 1, 'ch': 1, 'it': 1, 'es': 1, 'br': 1,
    'au': 1, 'in': 1, 'ru': 1, 'cn': 1,
    # Tier 2: Somewhat suspicious (cheap/free, often abused but also legitimate)
    'info': 2, 'biz': 2, 'me': 2, 'cc': 2, 'ws': 2, 'name': 2,
    'online': 2, 'site': 2, 'website': 2, 'space': 2, 'store': 2,
    'tech': 2, 'live': 2, 'cloud': 2, 'host': 2, 'fun': 2,
    'pro': 2, 'club': 2, 'world': 2, 'life': 2,
    # Tier 3: Very suspicious (heavily abused for phishing)
    'tk': 3, 'ml': 3, 'ga': 3, 'cf': 3, 'gq': 3,
    'xyz': 3, 'top': 3, 'pw': 3, 'su': 3,
    'buzz': 3, 'rest': 3, 'icu': 3, 'cam': 3, 'cfd': 3,
    'click': 3, 'link': 3, 'work': 3, 'monster': 3, 'sbs': 3,
}

# Well-known brand domains for impersonation detection
_BRAND_DOMAINS = {
    'google': 'google.com', 'facebook': 'facebook.com', 'meta': 'meta.com',
    'microsoft': 'microsoft.com', 'apple': 'apple.com', 'amazon': 'amazon.com',
    'netflix': 'netflix.com', 'paypal': 'paypal.com', 'instagram': 'instagram.com',
    'twitter': 'twitter.com', 'linkedin': 'linkedin.com', 'github': 'github.com',
    'dropbox': 'dropbox.com', 'chase': 'chase.com', 'wellsfargo': 'wellsfargo.com',
    'bankofamerica': 'bankofamerica.com', 'yahoo': 'yahoo.com', 'outlook': 'outlook.com',
    'spotify': 'spotify.com', 'steam': 'steampowered.com', 'discord': 'discord.com',
    'whatsapp': 'whatsapp.com', 'telegram': 'telegram.org', 'zoom': 'zoom.us',
    'adobe': 'adobe.com', 'shopee': 'shopee.vn', 'tiki': 'tiki.vn',
    'vietcombank': 'vietcombank.com.vn', 'techcombank': 'techcombank.com.vn',
}


# =============================================================================
# HELPER FUNCTIONS (used inside .apply())
# =============================================================================

def _safe_parse(url: str) -> tuple:
    """Safely parse a URL, adding scheme if missing. Returns (parsed, domain, path, query)."""
    url = str(url).strip()
    if not url:
        return urlparse(''), '', '', ''
    # Add scheme if missing so urlparse works correctly
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = 'http://' + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or ''
        path = parsed.path or ''
        query = parsed.query or ''
        return parsed, domain, path, query
    except Exception:
        return urlparse(''), '', '', ''


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string. High entropy = random/generated domain."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_ip_address(domain: str) -> int:
    """Check if domain is a raw IP address (IPv4 or IPv6)."""
    # Strip port if present
    host = domain.split(':')[0] if ':' in domain and '[' not in domain else domain
    host = host.strip('[]')
    try:
        ipaddress.ip_address(host)
        return 1
    except (ValueError, TypeError):
        return 0


def _count_subdomains(domain: str) -> int:
    """Count number of subdomain levels (e.g. 'a.b.example.com' -> 2 subdomains)."""
    if not domain:
        return 0
    # Strip port
    host = domain.split(':')[0]
    parts = host.split('.')
    # Typical domain = name.tld (2 parts) or name.co.uk (3 parts)
    # Anything beyond that is subdomains
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def _has_tld_in_path(path: str) -> int:
    """Check if a common TLD appears in the URL path (deceptive technique)."""
    path_lower = path.lower()
    for tld in COMMON_TLDS:
        if tld in path_lower:
            return 1
    return 0


def _is_shortened(domain: str) -> int:
    """Check if domain belongs to a known URL shortening service."""
    host = domain.lower().split(':')[0]
    if host in SHORTENING_SERVICES:
        return 1
    # Also check without www.
    if host.startswith('www.'):
        if host[4:] in SHORTENING_SERVICES:
            return 1
    return 0


def _count_query_params(query: str) -> int:
    """Count number of query parameters."""
    if not query:
        return 0
    try:
        return len(parse_qs(query, keep_blank_values=True))
    except Exception:
        return query.count('&') + (1 if query else 0)


def _tld_extract(url: str) -> tuple:
    """Extract (registered_domain, suffix/tld, subdomain) using tldextract."""
    try:
        ext = tldextract.extract(url)
        registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        return ext.domain, ext.suffix, ext.subdomain, registered
    except Exception:
        return '', '', '', ''


def _tld_reputation_score(suffix: str) -> int:
    """Return TLD reputation tier (0=trusted, 1=normal, 2=suspect, 3=very suspicious)."""
    if not suffix:
        return 2
    s = suffix.lower()
    if s in _TLD_REPUTATION:
        return _TLD_REPUTATION[s]
    # Unknown TLD defaults to somewhat suspicious
    return 2


def _vowel_consonant_ratio(text: str) -> float:
    """
    Ratio of vowels to consonants in a string.
    Random/generated domains have unusual ratios compared to real words.
    """
    if not text:
        return 0.0
    text = text.lower()
    vowels = sum(1 for c in text if c in 'aeiou')
    consonants = sum(1 for c in text if c.isalpha() and c not in 'aeiou')
    if consonants == 0:
        return float(vowels) if vowels > 0 else 0.0
    return round(vowels / consonants, 4)


def _domain_word_count(domain_name: str) -> int:
    """
    Estimate how many "words" are in the domain by splitting on dashes and
    checking for camelCase-like boundaries. Legitimate domains tend to be
    1-3 recognizable words; phishing domains are often random gibberish.
    """
    if not domain_name:
        return 0
    parts = re.split(r'[-_]', domain_name)
    return len([p for p in parts if p])


def _has_brand_impersonation(domain_name: str, registered_domain: str) -> int:
    """
    Detect if a brand keyword appears in the domain but the registered domain
    doesn't match the real brand. E.g. 'paypal-login.evil.com' contains 'paypal'
    but isn't paypal.com.
    """
    if not domain_name:
        return 0
    dn = domain_name.lower()
    rd = registered_domain.lower()
    for brand, real_domain in _BRAND_DOMAINS.items():
        if brand in dn and rd != real_domain:
            return 1
    return 0


def _consecutive_char_ratio(text: str) -> float:
    """
    Ratio of consecutive repeated characters. Random strings like 'xhm1w4'
    rarely have repeats, while 'google' has 'oo'. Very high repeats can
    also indicate generated domains like 'aaabbbccc'.
    """
    if not text or len(text) < 2:
        return 0.0
    repeats = sum(1 for i in range(1, len(text)) if text[i] == text[i - 1])
    return round(repeats / (len(text) - 1), 4)


def _digit_letter_ratio_domain(domain_name: str) -> float:
    """Ratio of digits to letters in the domain name (no TLD)."""
    if not domain_name:
        return 0.0
    digits = sum(1 for c in domain_name if c.isdigit())
    letters = sum(1 for c in domain_name if c.isalpha())
    if letters == 0:
        return float(digits) if digits > 0 else 0.0
    return round(digits / letters, 4)


# =============================================================================
# MAIN FEATURE EXTRACTION (Vectorized + .apply())
# =============================================================================

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract 40+ URL features optimized for XGBoost phishing detection.
    Uses vectorized operations and .apply() for performance on large datasets.
    
    Args:
        df: DataFrame with columns 'url' and 'label'
    
    Returns:
        DataFrame with all extracted features + original url and label
    """
    total = len(df)
    print(f"\n{'='*60}")
    print(f"  URL FEATURE EXTRACTION (Advanced)")
    print(f"  Processing {total:,} URLs...")
    print(f"{'='*60}")
    start_time = time.time()

    # --- Step 0: Normalize URLs ---
    df = df.copy()
    df['url'] = df['url'].astype(str).str.strip()
    # Handle unicode/encoding issues gracefully
    df['url'] = df['url'].apply(lambda u: u.encode('ascii', errors='ignore').decode('ascii') if u else '')
    
    # Pre-parse all URLs using .apply()
    print("[1/9] Parsing URLs...")
    parsed_data = df['url'].apply(_safe_parse)
    df['_parsed'] = parsed_data.apply(lambda x: x[0])
    df['_domain'] = parsed_data.apply(lambda x: x[1])
    df['_path'] = parsed_data.apply(lambda x: x[2])
    df['_query'] = parsed_data.apply(lambda x: x[3])
    df['_url_lower'] = df['url'].str.lower()
    df['_domain_lower'] = df['_domain'].str.lower()
    df['_path_lower'] = df['_path'].str.lower()
    # Strip "www." for cleaner domain analysis
    df['_domain_clean'] = df['_domain_lower'].str.replace(r'^www\.', '', regex=True)

    # =========================================================================
    # GROUP 1: LENGTH-BASED FEATURES
    # =========================================================================
    print("[2/9] Extracting length features...")
    result = pd.DataFrame()
    result['url'] = df['url']
    result['url_length'] = df['url'].str.len()
    result['hostname_length'] = df['_domain'].str.len()
    result['path_length'] = df['_path'].str.len()
    result['query_length'] = df['_query'].str.len()

    # =========================================================================
    # GROUP 2: COUNT-BASED FEATURES
    # =========================================================================
    print("[3/9] Extracting count features...")
    # Remove scheme for some counts (avoid counting :// slash)
    url_no_scheme = df['url'].str.replace(r'^https?://', '', regex=True)

    result['count_dot'] = df['url'].str.count(r'\.')
    result['count_dash'] = df['url'].str.count('-')
    result['count_at'] = df['url'].str.count('@')
    result['count_slash'] = url_no_scheme.str.count('/')
    result['count_question'] = df['url'].str.count(r'\?')
    result['count_equal'] = df['url'].str.count('=')
    result['count_ampersand'] = df['url'].str.count('&')
    result['count_hash'] = df['url'].str.count('#')
    result['count_percent'] = df['url'].str.count('%')
    result['count_underscore'] = df['url'].str.count('_')
    result['count_tilde'] = df['url'].str.count('~')
    result['count_http_in_url'] = df['_url_lower'].str.count('http')
    result['count_www_in_url'] = df['_url_lower'].str.count('www')
    result['count_digits_in_domain'] = df['_domain'].str.count(r'\d')
    result['count_query_params'] = df['_query'].apply(_count_query_params)

    # =========================================================================
    # GROUP 3: DOMAIN ANALYSIS (Advanced)
    # =========================================================================
    print("[4/9] Extracting domain analysis features...")
    # Shannon entropy of the domain name (high = randomly generated)
    result['domain_entropy'] = df['_domain_clean'].apply(_shannon_entropy)

    # Subdomain count
    result['subdomain_count'] = df['_domain'].apply(_count_subdomains)

    # Is domain a raw IP address?
    result['is_ip_address'] = df['_domain'].apply(_is_ip_address)

    # TLD appearing inside the path (deception: paypal.com-login.evil.com/path)
    result['has_tld_in_path'] = df['_path_lower'].apply(_has_tld_in_path)

    # Domain contains digits (suspicious pattern)
    result['domain_has_digits'] = (df['_domain'].str.contains(r'\d', regex=True, na=False)).astype(int)

    # Dots in domain (many dots = deep subdomain abuse)
    result['dots_in_domain'] = df['_domain'].str.count(r'\.')

    # =========================================================================
    # GROUP 4: KEYWORD DETECTION (Split: Domain vs Path for FPR reduction)
    # =========================================================================
    print("[5/9] Extracting keyword features...")
    # KEY INSIGHT: 'bank' in path of a news site is normal (low risk),
    # but 'bank' in the domain of an unknown site is high risk.
    # Splitting detection reduces False Positives significantly.
    
    for keyword in SUSPICIOUS_KEYWORDS:
        # Keyword present in the DOMAIN (high suspicion signal)
        result[f'kw_{keyword}_in_domain'] = df['_domain_lower'].str.contains(
            keyword, na=False, regex=False
        ).astype(int)
        
        # Keyword present in the PATH (weaker signal)
        result[f'kw_{keyword}_in_path'] = df['_path_lower'].str.contains(
            keyword, na=False, regex=False
        ).astype(int)

    # =========================================================================
    # GROUP 5: PROTOCOL & STRUCTURE FEATURES
    # =========================================================================
    print("[6/9] Extracting protocol & structure features...")
    result['is_https'] = df['_parsed'].apply(lambda p: 1 if p.scheme == 'https' else 0)
    result['has_port'] = df['_domain'].str.contains(r':\d+', regex=True, na=False).astype(int)
    result['has_fragment'] = df['url'].str.contains('#', na=False, regex=False).astype(int)
    
    # URL shortening service detection
    result['is_shortened'] = df['_domain'].apply(_is_shortened)

    # Double-slash in path (redirect trick: http://legit.com//evil.com)
    result['double_slash_in_path'] = df['_path'].str.contains('//', na=False, regex=False).astype(int)

    # @ sign in URL (redirect trick: http://legit.com@evil.com)
    result['has_at_sign'] = (result['count_at'] > 0).astype(int)

    # =========================================================================
    # GROUP 6: RATIO-BASED FEATURES
    # =========================================================================
    result['hostname_url_ratio'] = (
        result['hostname_length'] / result['url_length'].replace(0, 1)
    ).round(4)
    
    result['path_url_ratio'] = (
        result['path_length'] / result['url_length'].replace(0, 1)
    ).round(4)

    result['digits_to_url_ratio'] = (
        df['url'].str.count(r'\d') / result['url_length'].replace(0, 1)
    ).round(4)

    result['special_chars_ratio'] = (
        df['url'].str.count(r'[!@#$%^&*(),?\":{}\|<>]') / result['url_length'].replace(0, 1)
    ).round(4)

    # =========================================================================
    # GROUP 7: TLD REPUTATION (NEW — reduces FP on legitimate sites)
    # =========================================================================
    print("[7/9] Extracting TLD reputation features...")
    tld_data = df['url'].apply(_tld_extract)
    df['_tld_domain'] = tld_data.apply(lambda x: x[0])
    df['_tld_suffix'] = tld_data.apply(lambda x: x[1])
    df['_tld_subdomain'] = tld_data.apply(lambda x: x[2])
    df['_tld_registered'] = tld_data.apply(lambda x: x[3])

    result['tld_reputation'] = df['_tld_suffix'].apply(_tld_reputation_score)
    result['tld_is_suspicious'] = (result['tld_reputation'] >= 3).astype(int)
    result['tld_is_trusted'] = (result['tld_reputation'] == 0).astype(int)

    # Proper subdomain count using tldextract (more accurate than dot-counting)
    result['tld_subdomain_depth'] = df['_tld_subdomain'].apply(
        lambda s: len([p for p in s.split('.') if p]) if s else 0
    )

    # Domain name length (without TLD) — phishing domains are often very short or very long
    result['tld_domain_name_length'] = df['_tld_domain'].str.len().fillna(0).astype(int)

    # =========================================================================
    # GROUP 8: DOMAIN LINGUISTIC ANALYSIS (NEW — catches random/generated domains)
    # =========================================================================
    print("[8/9] Extracting domain linguistic features...")

    result['domain_vowel_consonant_ratio'] = df['_tld_domain'].apply(_vowel_consonant_ratio)
    result['domain_word_count'] = df['_tld_domain'].apply(_domain_word_count)
    result['domain_digit_letter_ratio'] = df['_tld_domain'].apply(_digit_letter_ratio_domain)
    result['domain_consecutive_char_ratio'] = df['_tld_domain'].apply(_consecutive_char_ratio)

    # Brand impersonation: hostname contains a brand name but registered domain
    # doesn't match the real brand (checks full hostname including subdomains)
    result['brand_impersonation'] = df.apply(
        lambda row: _has_brand_impersonation(row['_domain_clean'], row['_tld_registered']),
        axis=1
    )

    # Dash count in domain name (phishing loves: paypal-secure-login.com)
    result['domain_dash_count'] = df['_tld_domain'].str.count('-').fillna(0).astype(int)

    # Domain name looks random: high entropy + low vowel ratio + no dashes
    result['domain_looks_random'] = (
        (result['domain_entropy'] > 3.5) &
        (result['domain_vowel_consonant_ratio'] < 0.25) &
        (result['domain_dash_count'] == 0) &
        (result['tld_domain_name_length'] > 6)
    ).astype(int)

    # =========================================================================
    # GROUP 9: PATH & STRUCTURE DEPTH (NEW — normalize path_length impact)
    # =========================================================================
    print("[9/9] Extracting path structure features...")

    result['path_depth'] = df['_path'].apply(
        lambda p: len([s for s in p.split('/') if s]) if p else 0
    )
    result['path_has_extension'] = df['_path_lower'].str.contains(
        r'\.\w{2,5}$', regex=True, na=False
    ).astype(int)
    result['path_has_double_ext'] = df['_path_lower'].str.contains(
        r'\.\w{2,5}\.\w{2,5}$', regex=True, na=False
    ).astype(int)

    # =========================================================================
    # LABEL
    # =========================================================================
    result['label'] = df['label'].values

    # --- Cleanup internal columns ---
    # (only result DataFrame is returned, df internal cols are discarded)

    elapsed = time.time() - start_time
    feature_count = len(result.columns) - 2  # minus 'url' and 'label'
    print(f"\n{'='*60}")
    print(f"  EXTRACTION COMPLETE")
    print(f"  {feature_count} features extracted for {total:,} URLs")
    print(f"  Time elapsed: {elapsed:.1f}s")
    print(f"{'='*60}")

    return result


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  PHISHING URL FEATURE EXTRACTION PIPELINE")
    print("=" * 60)

    # --- Load both datasets ---
    dfs = []

    if os.path.exists(PHISHING_FILE):
        phishing_df = pd.read_csv(PHISHING_FILE)
        # Ensure label column exists
        if 'label' not in phishing_df.columns:
            phishing_df['label'] = 1
        phishing_df = phishing_df[['url', 'label']].copy()
        print(f"  Phishing URLs loaded: {len(phishing_df):,}")
        dfs.append(phishing_df)
    else:
        print(f"  WARNING: Phishing file not found: {PHISHING_FILE}")

    if os.path.exists(BENIGN_FILE):
        benign_df = pd.read_csv(BENIGN_FILE)
        if 'label' not in benign_df.columns:
            benign_df['label'] = 0
        benign_df = benign_df[['url', 'label']].copy()
        print(f"  Benign URLs loaded:   {len(benign_df):,}")
        dfs.append(benign_df)
    else:
        print(f"  WARNING: Benign file not found: {BENIGN_FILE}")

    if not dfs:
        print("\nERROR: No data files found! Exiting.")
        exit(1)

    # Combine and shuffle
    combined_df = pd.concat(dfs, ignore_index=True)
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"\n  Combined dataset: {len(combined_df):,} URLs")
    print(f"    - Phishing (label=1): {(combined_df['label']==1).sum():,}")
    print(f"    - Benign   (label=0): {(combined_df['label']==0).sum():,}")

    # --- Extract Features ---
    feature_df = extract_features(combined_df)

    # --- Save ---
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    feature_df.to_csv(OUTPUT_FILE, index=False)
    
    print(f"\n  Output saved to: {OUTPUT_FILE}")
    print(f"  File size: {os.path.getsize(OUTPUT_FILE) / 1024 / 1024:.1f} MB")
    print(f"  Shape: {feature_df.shape[0]:,} rows x {feature_df.shape[1]} columns")
    
    # --- Feature summary ---
    print(f"\n  Feature columns ({len(feature_df.columns) - 2}):")
    for col in sorted(feature_df.columns):
        if col not in ('url', 'label'):
            print(f"    - {col}")