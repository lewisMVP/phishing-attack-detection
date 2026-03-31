"""
PhishTank Data Source
Downloads verified active phishing URLs directly from the PhishTank CSV dump.
"""
import pandas as pd
import requests
import io


# Required CSV endpoint
PHISHTANK_CSV_URL = "http://data.phishtank.com/data/online-valid.csv"


def collect_phishtank():
    """
    Download verified active phishing URLs from PhishTank in CSV format.
    
    Returns:
        pd.DataFrame with columns: url, source
    """
    print("\n" + "=" * 60)
    print(f"[PhishTank] Downloading CSV format from: {PHISHTANK_CSV_URL}")
    print("=" * 60)

    # Standard browser User-Agent to avoid basic blocks
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }

    try:
        response = requests.get(PHISHTANK_CSV_URL, headers=headers, timeout=60)
        
        # Check for rate limiting
        if response.status_code == 429:
            print("[PhishTank] ERROR: Rate limited (429 Too Many Requests).")
            return pd.DataFrame()
            
        response.raise_for_status()
        
        # Read the raw downloaded CSV text directly into Pandas
        df = pd.read_csv(io.StringIO(response.text))
        
        if 'url' not in df.columns:
            print("[PhishTank] ERROR: 'url' column not found in the downloaded CSV.")
            return pd.DataFrame()

        # Keep only the target column
        df = df[['url']].copy()
        df['source'] = 'phishtank'
        
        # Basic cleaning
        df = df.dropna(subset=['url'])
        df['url'] = df['url'].str.strip()
        
        print(f"[PhishTank] Successfully collected {len(df)} verified phishing URLs.")
        return df

    except requests.exceptions.HTTPError as e:
        print(f"[PhishTank] ERROR: HTTP Error - {e}")
        return pd.DataFrame()
    except requests.exceptions.Timeout:
        print("[PhishTank] ERROR: Connection timed out.")
        return pd.DataFrame()
    except Exception as e:
        print(f"[PhishTank] ERROR: Unexpected error - {e}")
        return pd.DataFrame()


if __name__ == "__main__":
    df = collect_phishtank()
    if not df.empty:
        print(df.head())
        print(f"\nTotal entries: {len(df)}")
