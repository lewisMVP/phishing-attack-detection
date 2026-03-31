"""
OpenPhish Data Source
Downloads phishing URLs from OpenPhish Community Feed (free tier).
Feed URL: https://openphish.com/feed.txt (updated every 6-12 hours)
"""
import pandas as pd
import requests


def collect_openphish():
    """
    Download phishing URLs from OpenPhish community feed.
    The free feed contains a subset of all detected phishing URLs,
    updated approximately every 6-12 hours.
    
    Returns:
        pd.DataFrame with columns: url, source
        Returns empty DataFrame on failure.
    """
    url = "https://openphish.com/feed.txt"
    print("\n" + "=" * 60)
    print("[OpenPhish] Downloading community phishing feed...")
    print("=" * 60)

    try:
        headers = {
            'User-Agent': 'phishing-research-project/2.0 (academic research)'
        }
        response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()

        # feed.txt is a plain text file with one URL per line
        lines = response.text.strip().split('\n')
        urls = [line.strip() for line in lines if line.strip()]

        if not urls:
            print("[OpenPhish] WARNING: Feed is empty.")
            return pd.DataFrame(columns=['url', 'source'])

        df = pd.DataFrame({'url': urls})
        df['source'] = 'openphish'

        # Remove duplicates within this source
        df = df.drop_duplicates(subset=['url'])

        print(f"[OpenPhish] Successfully collected {len(df)} phishing URLs.")
        return df

    except requests.exceptions.Timeout:
        print("[OpenPhish] ERROR: Request timed out (60s).")
        return pd.DataFrame(columns=['url', 'source'])
    except requests.exceptions.RequestException as e:
        print(f"[OpenPhish] ERROR: Network error - {e}")
        return pd.DataFrame(columns=['url', 'source'])
    except Exception as e:
        print(f"[OpenPhish] ERROR: {e}")
        return pd.DataFrame(columns=['url', 'source'])


if __name__ == "__main__":
    df = collect_openphish()
    if not df.empty:
        print(f"\nSample URLs:")
        print(df.head(10).to_string(index=False))
        print(f"\nTotal: {len(df)} URLs")
