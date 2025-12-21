import pandas as pd
from urllib.parse import urlparse
import re
import os
import ipaddress

# --- CONFIGURATION ---
INPUT_FILE = '../../data/processed/downloaded_log.csv'
OUTPUT_FILE = '../../data/datasets/url_features_dataset.csv'

def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return 1
    except:
        return 0

def count_special_chars(url):
    return len(re.findall(r'[!@#$%^&*(),?":{}|<>]', url))

def extract_features(df):
    features = []
    print(f"Extracting features for {len(df)} URLs...")

    for index, row in df.iterrows():
        url = str(row['url']).strip()
        label = row['label']
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            url_calc = url.replace("://", "")

            f_data = {
                'url': url,
                'url_length': len(url),
                'hostname_length': len(domain),
                'path_length': len(path),
                'count_at': url.count('@'),
                'count_dash': url.count('-'),
                'count_dot': url.count('.'),
                'count_slash': url_calc.count('/'), 
                'count_question': url.count('?'),
                'count_equal': url.count('='),
                'count_http': url.count('http'),
                'count_www': url.count('www'),
                'count_special': count_special_chars(url),
                'is_https': 1 if parsed_url.scheme == 'https' else 0,
                'is_ip': is_ip_address(domain),
                'has_login': 1 if 'login' in url.lower() else 0,
                'has_secure': 1 if 'secure' in url.lower() else 0,
                'has_account': 1 if 'account' in url.lower() else 0,
                'has_verify': 1 if 'verify' in url.lower() else 0,
                'has_signin': 1 if 'signin' in url.lower() else 0,
                'has_bank': 1 if 'bank' in url.lower() else 0,
                'has_confirm': 1 if 'confirm' in url.lower() else 0,
                'label': label 
            }
            features.append(f_data)
            
        except Exception as e:
            print(f"Error processing URL at index {index}: {url} - {e}")

    return pd.DataFrame(features)

if __name__ == "__main__":
    print("Loading data from log file...")
    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: File not found: {INPUT_FILE}")
        exit()
        
    df = pd.read_csv(INPUT_FILE)
    print(f"Loaded {len(df)} URLs.")
    
    # Extract & Save
    feature_df = extract_features(df)
    os.makedirs('../../data/datasets/', exist_ok=True)
    feature_df.to_csv(OUTPUT_FILE, index=False)
    print(f"SUCCESS! Saved to: {OUTPUT_FILE}")