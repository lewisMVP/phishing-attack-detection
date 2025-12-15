import pandas as pd
import requests
import io

def download_phishtank_data():
    url = "http://data.phishtank.com/data/online-valid.csv"
    print("Downloading data from PhishTank... (This may take a few minutes)")
    
    try:
        # Simulate User-Agent to avoid being blocked
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        s = requests.get(url, headers=headers).content
        
        # Read data into Pandas DataFrame
        data = pd.read_csv(io.StringIO(s.decode('utf-8')))
        
        # Filter data: Only take 'url' and 'phish_id' columns
        # Note: The online-valid.csv file from PhishTank usually contains live links
        phishing_urls = data[['url']].copy()
        phishing_urls['label'] = 1 # Assign label 1 for Phishing
        
        # Save results
        output_path = '../../data/processed/phishing_urls.csv'
        phishing_urls.to_csv(output_path, index=False)
        print(f"Saved {len(phishing_urls)} phishing URLs to {output_path}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    download_phishtank_data()