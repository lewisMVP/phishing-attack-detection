import pandas as pd
import requests
import zipfile
import io

def download_tranco_list():
    # Using Tranco list (Top 1M popular sites)
    url = "https://tranco-list.eu/top-1m.csv.zip"
    print("Downloading Tranco Top 1M list...")
    
    try:
        r = requests.get(url)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        
        # Read CSV file from within the zip (usually no header)
        with z.open('top-1m.csv') as f:
            data = pd.read_csv(f, header=None, names=['rank', 'url'])
        
        # Get the first 10,000 URLs (most popular)
        benign_urls = data[['url']].head(10000).copy()
        
        # Normalize URLs (Add http/https because the original list usually contains only domains)
        # Note: Next week when crawling content, we will check whether it is http or https.
        # Here we temporarily add a prefix for consistency.
        benign_urls['url'] = 'http://' + benign_urls['url'] 
        benign_urls['label'] = 0 # Label 0 means Benign (Safe)
        
        # Save results
        output_path = '../../data/processed/benign_urls.csv'
        benign_urls.to_csv(output_path, index=False)
        print(f"Saved {len(benign_urls)} benign URLs to {output_path}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    download_tranco_list()