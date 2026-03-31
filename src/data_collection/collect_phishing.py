"""
Phishing URL Collection - Main Aggregator
Collects phishing URLs from multiple sources:
  1. Phishing.Database (GitHub - replaces PhishTank, 782K+ active links)
  2. OpenPhish (community feed, ~300 URLs)  
  3. PhishStats (API with scoring, graceful degradation)

Merges, deduplicates, and saves to data/processed/phishing_urls.csv
Target: ~15,000 unique phishing URLs
"""
import pandas as pd
import os
import sys
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phishtank_source import collect_phishtank
from openphish_source import collect_openphish
from phishstats_source import collect_phishstats


# --- CONFIGURATION ---
TARGET_URLS = 15000
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'processed')
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'phishing_urls.csv')

# Phishing.Database: max URLs to sample from (they have 782K+)
PHISHING_DB_MAX = 10000

# PhishStats config
PHISHSTATS_PAGES = 50       # 50 pages = up to 5,000 URLs
PHISHSTATS_MIN_SCORE = 3


def collect_all_phishing():
    """
    Collect phishing URLs from all sources, merge, deduplicate, and save.
    """
    print("=" * 60)
    print("  PHISHING URL COLLECTION - MULTI-SOURCE AGGREGATOR")
    print(f"  Target: {TARGET_URLS} unique URLs")
    print(f"  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # --- 1. Collect from each source ---
    print("\n[STEP 1/4] Collecting from all sources...\n")

    # Source 1: PhishTank (JSON endpoint)
    phishtank_df = collect_phishtank()

    # Source 2: OpenPhish (community feed)
    openphish_df = collect_openphish()

    # Source 3: PhishStats (API - may timeout, graceful degradation)
    phishstats_df = collect_phishstats(
        total_pages=PHISHSTATS_PAGES,
        min_score=PHISHSTATS_MIN_SCORE
    )

    # --- 2. Merge all sources ---
    print("\n[STEP 2/4] Merging all sources...")
    
    all_dfs = []
    source_stats = {}
    
    for name, df in [('PhishTank', phishtank_df), 
                     ('OpenPhish', openphish_df), 
                     ('PhishStats', phishstats_df)]:
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
    print(f"\n  Total before dedup: {total_before_dedup}")

    # --- 3. Deduplicate ---
    print("\n[STEP 3/4] Deduplicating URLs...")
    
    # Normalize URLs for better dedup (lowercase, strip whitespace)
    combined['url_normalized'] = combined['url'].str.strip().str.lower()
    combined = combined.drop_duplicates(subset=['url_normalized'], keep='first')
    combined = combined.drop(columns=['url_normalized'])
    
    duplicates_removed = total_before_dedup - len(combined)
    print(f"  Duplicates removed: {duplicates_removed}")
    print(f"  Unique URLs: {len(combined)}")

    # --- 4. Add metadata, label, and save ---
    print("\n[STEP 4/4] Saving results...")
    
    combined['label'] = 1  # Phishing label
    combined['collected_at'] = datetime.now().isoformat()
    
    # Trim to target if we have more than needed
    if len(combined) > TARGET_URLS:
        print(f"  Trimming from {len(combined)} to {TARGET_URLS} URLs...")
        
        # Keep all URLs from minority sources, randomly sample from the majority
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
    print(f"\n  Source breakdown (raw):")
    for source_name, count in source_stats.items():
        print(f"    - {source_name}: {count} URLs")
    print(f"    - Duplicates removed: {duplicates_removed}")
    
    # Per-source breakdown in final dataset
    print(f"\n  In final dataset:")
    for source, count in combined['source'].value_counts().items():
        pct = count / len(combined) * 100
        print(f"    - {source}: {count} URLs ({pct:.1f}%)")
    
    print(f"\n  Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


if __name__ == "__main__":
    collect_all_phishing()
