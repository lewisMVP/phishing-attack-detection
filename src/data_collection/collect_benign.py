"""
Benign URL Collection - Multi-Source Aggregator
Collects benign (safe) URLs from multiple sources:
  1. Tranco List (Top 1M popular domains)
  2. Common Crawl CDX API (real URLs with paths from popular domains)

Merges, deduplicates, and saves to data/processed/benign_urls.csv
Target: ~15,000 unique benign URLs
"""
import pandas as pd
import requests
import zipfile
import io
import os
import time
import json
import random
from datetime import datetime


# --- CONFIGURATION ---
TARGET_URLS = 15000
TRANCO_COUNT = 10000         # Number of domains from Tranco Top 1M
CC_URLS_PER_DOMAIN = 10      # Max URLs to collect per domain from Common Crawl
CC_DOMAINS_TO_QUERY = 800    # Number of Tranco domains to query in Common Crawl
CC_TARGET = 6000             # Target URLs from Common Crawl
CC_REQUEST_TIMEOUT = 30      # Timeout for CC API requests
CC_DELAY_BETWEEN_REQUESTS = 1.5  # Seconds between CC API calls (be polite)

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'processed')
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'benign_urls.csv')


def download_tranco_list(count=TRANCO_COUNT):
    """
    Download benign domains from Tranco Top 1M list.
    Returns DataFrame with columns: url, source
    """
    url = "https://tranco-list.eu/top-1m.csv.zip"
    print("\n" + "=" * 60)
    print("[Tranco] Downloading Top 1M list...")
    print("=" * 60)

    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        z = zipfile.ZipFile(io.BytesIO(response.content))

        with z.open('top-1m.csv') as f:
            data = pd.read_csv(f, header=None, names=['rank', 'domain'])

        # Take top N domains
        domains = data['domain'].head(count).tolist()
        
        # Convert domains to URLs with http:// prefix
        urls = [f"http://{domain}" for domain in domains]
        
        df = pd.DataFrame({
            'url': urls,
            'source': 'tranco'
        })

        print(f"[Tranco] Successfully collected {len(df)} benign URLs.")
        return df, domains  # Also return raw domains for Common Crawl

    except Exception as e:
        print(f"[Tranco] ERROR: {e}")
        return pd.DataFrame(columns=['url', 'source']), []


def collect_from_commoncrawl(domains, target_urls=CC_TARGET, 
                              urls_per_domain=CC_URLS_PER_DOMAIN):
    """
    Query Common Crawl CDX API to collect real URLs (with paths) 
    from popular domains. This gives us diverse URLs beyond just root domains.
    
    Args:
        domains: List of domain names to query
        target_urls: Total target URLs to collect
        urls_per_domain: Max URLs per domain
    
    Returns:
        pd.DataFrame with columns: url, source
    """
    print("\n" + "=" * 60)
    print("[CommonCrawl] Querying CDX API for diverse URLs...")
    print(f"[CommonCrawl] Querying up to {CC_DOMAINS_TO_QUERY} domains, "
          f"{urls_per_domain} URLs each")
    print(f"[CommonCrawl] Target: {target_urls} URLs")
    print("=" * 60)

    # Use a subset of domains (prioritize top-ranked but add some randomness)
    # Take top 200 + random sample from rest
    top_domains = domains[:200]
    if len(domains) > 200:
        remaining = domains[200:min(2000, len(domains))]
        random_sample_size = min(CC_DOMAINS_TO_QUERY - 200, len(remaining))
        random_domains = random.sample(remaining, random_sample_size)
        query_domains = top_domains + random_domains
    else:
        query_domains = top_domains

    all_urls = []
    consecutive_errors = 0
    max_consecutive_errors = 10
    domains_processed = 0

    # Common Crawl CDX API - use latest index
    cdx_api = "https://index.commoncrawl.org/CC-MAIN-2025-08-index"

    headers = {
        'User-Agent': 'phishing-research-project/2.0 (academic research)'
    }

    for domain in query_domains:
        if len(all_urls) >= target_urls:
            print(f"\n[CommonCrawl] Reached target of {target_urls} URLs.")
            break

        try:
            params = {
                'url': f'*.{domain}/*',
                'output': 'json',
                'fl': 'url,status',
                'filter': '=status:200',  # Only successful pages
                'limit': urls_per_domain
            }

            response = requests.get(
                cdx_api, 
                params=params, 
                headers=headers,
                timeout=CC_REQUEST_TIMEOUT
            )

            if response.status_code == 404:
                # Index not found, try without specific version
                cdx_api_fallback = "https://index.commoncrawl.org/CC-MAIN-2024-51-index"
                response = requests.get(
                    cdx_api_fallback,
                    params=params,
                    headers=headers,
                    timeout=CC_REQUEST_TIMEOUT
                )

            if response.status_code != 200:
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    print(f"\n[CommonCrawl] Too many errors ({consecutive_errors}). Stopping.")
                    break
                continue

            # Parse JSONL response (one JSON object per line)
            lines = response.text.strip().split('\n')
            domain_urls = []
            
            for line in lines:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    url_value = entry.get('url', '').strip()
                    if url_value and url_value.startswith('http'):
                        domain_urls.append(url_value)
                except json.JSONDecodeError:
                    continue

            if domain_urls:
                # Deduplicate within this domain
                domain_urls = list(set(domain_urls))[:urls_per_domain]
                all_urls.extend(domain_urls)
                consecutive_errors = 0

            domains_processed += 1
            if domains_processed % 50 == 0:
                print(f"[CommonCrawl] Processed {domains_processed} domains, "
                      f"collected {len(all_urls)} URLs...")

            # Be polite to the API
            time.sleep(CC_DELAY_BETWEEN_REQUESTS)

        except requests.exceptions.Timeout:
            consecutive_errors += 1
            if consecutive_errors >= max_consecutive_errors:
                print(f"\n[CommonCrawl] Too many timeouts. Stopping.")
                break
            time.sleep(CC_DELAY_BETWEEN_REQUESTS * 2)
            continue
        except Exception as e:
            consecutive_errors += 1
            if consecutive_errors >= max_consecutive_errors:
                print(f"\n[CommonCrawl] Too many errors: {e}. Stopping.")
                break
            time.sleep(CC_DELAY_BETWEEN_REQUESTS)
            continue

    if not all_urls:
        print("[CommonCrawl] WARNING: No URLs collected.")
        return pd.DataFrame(columns=['url', 'source'])

    df = pd.DataFrame({'url': all_urls})
    df['source'] = 'commoncrawl'
    df = df.drop_duplicates(subset=['url'])

    print(f"\n[CommonCrawl] Successfully collected {len(df)} unique benign URLs "
          f"from {domains_processed} domains.")
    return df


def collect_all_benign():
    """
    Collect benign URLs from all sources, merge, deduplicate, and save.
    """
    print("=" * 60)
    print("  BENIGN URL COLLECTION - MULTI-SOURCE AGGREGATOR")
    print(f"  Target: {TARGET_URLS} unique URLs")
    print(f"  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # --- 1. Collect from Tranco ---
    print("\n[STEP 1/4] Collecting from Tranco List...")
    tranco_df, tranco_domains = download_tranco_list()

    # --- 2. Collect from Common Crawl ---
    print("\n[STEP 2/4] Collecting from Common Crawl CDX API...")
    if tranco_domains:
        commoncrawl_df = collect_from_commoncrawl(tranco_domains)
    else:
        print("[CommonCrawl] SKIPPED: No Tranco domains available for querying.")
        commoncrawl_df = pd.DataFrame(columns=['url', 'source'])

    # --- 3. Merge & Deduplicate ---
    print("\n[STEP 3/4] Merging and deduplicating...")
    
    all_dfs = []
    source_stats = {}
    
    for name, df in [('Tranco', tranco_df), ('CommonCrawl', commoncrawl_df)]:
        if not df.empty:
            all_dfs.append(df)
            source_stats[name] = len(df)
            print(f"  {name}: {len(df)} URLs")
        else:
            source_stats[name] = 0
            print(f"  {name}: 0 URLs (FAILED or EMPTY)")

    if not all_dfs:
        print("\nERROR: No data collected from any source!")
        return

    combined = pd.concat(all_dfs, ignore_index=True)
    total_before_dedup = len(combined)

    # Normalize and deduplicate
    combined['url_normalized'] = combined['url'].str.strip().str.lower()
    combined = combined.drop_duplicates(subset=['url_normalized'], keep='first')
    combined = combined.drop(columns=['url_normalized'])

    duplicates_removed = total_before_dedup - len(combined)
    print(f"  Duplicates removed: {duplicates_removed}")
    print(f"  Unique URLs: {len(combined)}")

    # --- 4. Add metadata, label, and save ---
    print("\n[STEP 4/4] Saving results...")
    
    combined['label'] = 0  # Benign label
    combined['collected_at'] = datetime.now().isoformat()
    
    # Trim to target if needed
    if len(combined) > TARGET_URLS:
        print(f"  Trimming from {len(combined)} to {TARGET_URLS} URLs...")
        
        # Keep all URLs from minority sources, and randomly sample from the majority source
        final_dfs = []
        remaining_target = TARGET_URLS
        
        source_sizes = combined['source'].value_counts().sort_values()
        
        for source, count in source_sizes.items():
            source_df = combined[combined['source'] == source]
            sources_left = len(source_sizes) - list(source_sizes.index).index(source)
            fair_share = remaining_target // sources_left
            
            if len(source_df) <= fair_share:
                final_dfs.append(source_df)
                remaining_target -= len(source_df)
            else:
                sampled = source_df.sample(n=fair_share, random_state=42)
                final_dfs.append(sampled)
                remaining_target -= fair_share
                
        # Combine back and shuffle the final dataset
        combined = pd.concat(final_dfs).sample(frac=1, random_state=42).reset_index(drop=True)

    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Save
    combined.to_csv(OUTPUT_FILE, index=False)

    # --- Final Report ---
    print("\n" + "=" * 60)
    print("  COLLECTION COMPLETE!")
    print("=" * 60)
    print(f"  Output file: {OUTPUT_FILE}")
    print(f"  Total unique URLs saved: {len(combined)}")
    print(f"\n  Source breakdown:")
    for source_name, count in source_stats.items():
        print(f"    - {source_name}: {count} URLs (raw)")
    print(f"    - Duplicates removed: {duplicates_removed}")
    
    print(f"\n  In final dataset:")
    for source, count in combined['source'].value_counts().items():
        pct = count / len(combined) * 100
        print(f"    - {source}: {count} URLs ({pct:.1f}%)")
    
    print(f"\n  Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


if __name__ == "__main__":
    collect_all_benign()