import pandas as pd
from urllib.parse import urlparse
import re
import os
import ipaddress

# --- CONFIGURATION ---
# Input: The log file containing URLs that were successfully downloaded
INPUT_FILE = '../../data/processed/downloaded_log.csv'
# Output: The CSV file containing numerical features for training
OUTPUT_FILE = '../../data/datasets/url_features_dataset.csv'

def is_ip_address(domain):
    """
    Check if the domain is an IP address (e.g., 192.168.1.1).
    Phishing sites often use IPs instead of domain names.
    """
    try:
        ipaddress.ip_address(domain)
        return 1
    except:
        return 0

def count_special_chars(url):
    """
    Count total special characters in the URL.
    """
    return len(re.findall(r'[!@#$%^&*(),?":{}|<>]', url))

def extract_features(df):
    """
    Extract lexical features from URLs.
    Ref: Project Outline Section 5.2 & 3.3.1
    """
    features = []
    
    print(f"Extracting features for {len(df)} URLs...")

    for index, row in df.iterrows():
        url = str(row['url']).strip()
        label = row['label']
        
        try:
            # Parse the URL to separate domain, path, etc.
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # --- FEATURE ENGINEERING ---
            f_data = {
                'url': url,
                
                # 1. Length Features [cite: 20, 44]
                'url_length': len(url),
                'hostname_length': len(domain),
                'path_length': len(path),
                
                # 2. Character Counts 
                'count_at': url.count('@'),            # Phishers use @ to trick browsers
                'count_dash': url.count('-'),          # Dash is common in typosquatting
                'count_dot': url.count('.'),           # Multiple dots (e.g. .com.badsite.net)
                'count_slash': url.count('/'),         # Deep paths
                'count_question': url.count('?'),      # Query parameters
                'count_equal': url.count('='),
                'count_http': url.count('http'),       # Check for double http (redirects)
                'count_www': url.count('www'),
                'count_special': count_special_chars(url),
                
                # 3. Binary Features (0 or 1) 
                'is_https': 1 if parsed_url.scheme == 'https' else 0,
                'is_ip': is_ip_address(domain),        # Check if domain is an IP
                
                # 4. Phishing Keywords in URL [cite: 48]
                # Checking if sensitive words appear in the URL string
                'has_login': 1 if 'login' in url.lower() else 0,
                'has_secure': 1 if 'secure' in url.lower() else 0,
                'has_account': 1 if 'account' in url.lower() else 0,
                'has_verify': 1 if 'verify' in url.lower() else 0,
                'has_signin': 1 if 'signin' in url.lower() else 0,
                'has_bank': 1 if 'bank' in url.lower() else 0,
                'has_confirm': 1 if 'confirm' in url.lower() else 0,
                
                # Target Label
                'label': label 
            }
            features.append(f_data)
            
        except Exception as e:
            # Log error but verify if it's just a malformed URL
            print(f"Error processing URL at index {index}: {url} - {e}")

    return pd.DataFrame(features)

if __name__ == "__main__":
    # 1. Load Data
    print("Loading data from log file...")
    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: File not found: {INPUT_FILE}")
        print("Please ensure you have completed the Data Collection step (Week 1-2).")
        exit()
        
    df = pd.read_csv(INPUT_FILE)
    print(f"Loaded {len(df)} URLs.")
    
    # 2. Extract Features
    feature_df = extract_features(df)
    
    # 3. Save Data
    os.makedirs('../../data/datasets/', exist_ok=True)
    feature_df.to_csv(OUTPUT_FILE, index=False)
    
    print("-" * 30)
    print(f"SUCCESS! Extracted features for {len(feature_df)} URLs.")
    print(f"Saved to: {OUTPUT_FILE}")
    print("-" * 30)
    print("Preview (First 5 rows):")
    print(feature_df.head())