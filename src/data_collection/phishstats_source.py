"""
PhishStats Data Source
Collects phishing URLs from PhishStats API.
API: https://api.phishstats.info/api/phishing

Features:
- Robust retry with exponential backoff
- Graceful degradation: returns whatever data was collected if API becomes unavailable
- Configurable page count and score filter
- Rate limit: 20 requests/minute (official)
"""
import pandas as pd
import requests
import time


# --- CONFIGURATION ---
API_BASE = "https://api.phishstats.info/api/phishing"
MAX_PER_PAGE = 100          # API max per request
DEFAULT_TOTAL_PAGES = 50    # 50 pages x 100 = 5,000 URLs target
REQUEST_TIMEOUT = 10        # seconds (lowered so it gracefully degrades faster)
DELAY_BETWEEN_REQUESTS = 4  # 4 seconds = ~15 req/min (under 20 req/min limit)
MAX_RETRIES_PER_PAGE = 1    # Retry each failed page up to 1 times
RETRY_BACKOFF = 3           # Base wait time for retries


def collect_phishstats(total_pages=DEFAULT_TOTAL_PAGES, min_score=3):
    """
    Collect phishing URLs from PhishStats API with pagination.
    Gracefully stops and returns partial data if the API becomes unreachable.
    
    Args:
        total_pages: Number of pages to fetch (each page = up to 100 records).
        min_score: Minimum phishing score filter (higher = more confident).
    
    Returns:
        pd.DataFrame with columns: url, source
        Returns empty DataFrame on complete failure.
    """
    print("\n" + "=" * 60)
    print(f"[PhishStats] Collecting phishing URLs via API...")
    print(f"[PhishStats] Config: {total_pages} pages, min_score={min_score}")
    print(f"[PhishStats] Estimated time: ~{(total_pages * DELAY_BETWEEN_REQUESTS) // 60} minutes")
    print("=" * 60)

    all_records = []
    consecutive_errors = 0
    max_consecutive_errors = 3  # Stop early if API is clearly down

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    for page in range(1, total_pages + 1):
        params = {
            '_where': f'(score,gt,{min_score})',
            '_sort': '-date',
            '_size': MAX_PER_PAGE,
            '_p': page
        }

        success = False
        for retry in range(MAX_RETRIES_PER_PAGE + 1):
            try:
                response = requests.get(
                    API_BASE,
                    params=params,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT
                )

                # Handle rate limiting (HTTP 429)
                if response.status_code == 429:
                    wait_time = RETRY_BACKOFF * (retry + 2)
                    print(f"[PhishStats] Rate limited! Waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue

                response.raise_for_status()
                data = response.json()

                if not data or len(data) == 0:
                    print(f"[PhishStats] Page {page}: No more data. Stopping.")
                    # This is a normal end, not an error
                    consecutive_errors = max_consecutive_errors  # triggers clean exit
                    success = True
                    break

                # Extract URLs from JSON response
                page_urls = 0
                for entry in data:
                    url_value = entry.get('url', '').strip()
                    if url_value:
                        all_records.append({
                            'url': url_value,
                            'source': 'phishstats'
                        })
                        page_urls += 1

                print(f"[PhishStats] Page {page}/{total_pages}: +{page_urls} URLs "
                      f"(total: {len(all_records)})")

                consecutive_errors = 0
                success = True
                break  # Exit retry loop on success

            except (requests.exceptions.Timeout, 
                    requests.exceptions.ConnectionError,
                    TimeoutError) as e:
                # Catching WinError 10060 socket timeout that bypasses requests exceptions
                if retry < MAX_RETRIES_PER_PAGE:
                    wait_time = RETRY_BACKOFF * (retry + 1)
                    print(f"[PhishStats] Page {page}: Connection issue, "
                          f"retry {retry + 1}/{MAX_RETRIES_PER_PAGE} in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    print(f"[PhishStats] Page {page}: Failed after {MAX_RETRIES_PER_PAGE} retries.")
                    consecutive_errors += 1

            except requests.exceptions.RequestException as e:
                print(f"[PhishStats] Page {page}: HTTP error - {e}")
                consecutive_errors += 1
                break  # Don't retry on HTTP errors (4xx, 5xx)

            except Exception as e:
                print(f"[PhishStats] Page {page}: Unexpected error - {e}")
                consecutive_errors += 1
                break

        # Check if we should stop
        if consecutive_errors >= max_consecutive_errors:
            if all_records:
                print(f"[PhishStats] API unreachable. Saving {len(all_records)} URLs collected so far.")
            else:
                print("[PhishStats] API unreachable. No data collected.")
            break

        # Delay between successful requests
        if success and page < total_pages:
            time.sleep(DELAY_BETWEEN_REQUESTS)

    if not all_records:
        print("[PhishStats] WARNING: No URLs collected.")
        return pd.DataFrame(columns=['url', 'source'])

    df = pd.DataFrame(all_records)
    df = df.drop_duplicates(subset=['url'])

    print(f"\n[PhishStats] Successfully collected {len(df)} unique phishing URLs.")
    return df


if __name__ == "__main__":
    # Quick test with 3 pages only
    df = collect_phishstats(total_pages=3, min_score=3)
    if not df.empty:
        print(f"\nSample URLs:")
        print(df.head(10).to_string(index=False))
        print(f"\nTotal: {len(df)} URLs")
