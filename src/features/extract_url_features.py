"""
Advanced URL Feature Extraction for XGBoost Phishing Detection
==============================================================
Extracts 40+ features from URLs optimized for minimizing False Positive Rate.

Features are grouped into 7 categories:
  1. Length-based features
  2. Count-based features  
  3. Domain analysis (entropy, subdomain depth, TLD-in-path)
  4. Keyword detection (split by domain vs path for FPR reduction)
  5. Protocol & structure features
  6. Ratio-based features
  7. Shortening service detection

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
    print("[1/7] Parsing URLs...")
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
    print("[2/7] Extracting length features...")
    result = pd.DataFrame()
    result['url'] = df['url']
    result['url_length'] = df['url'].str.len()
    result['hostname_length'] = df['_domain'].str.len()
    result['path_length'] = df['_path'].str.len()
    result['query_length'] = df['_query'].str.len()

    # =========================================================================
    # GROUP 2: COUNT-BASED FEATURES
    # =========================================================================
    print("[3/7] Extracting count features...")
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
    print("[4/7] Extracting domain analysis features...")
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
    print("[5/7] Extracting keyword features...")
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
    print("[6/7] Extracting protocol & structure features...")
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