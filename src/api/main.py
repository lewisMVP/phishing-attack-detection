from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import os
import base64
import io
import torch
import numpy as np
from PIL import Image
from transformers import BertTokenizer, BertForSequenceClassification
from ultralytics import YOLO
from urllib.parse import urlparse
import re
import ipaddress
from fastapi.middleware.cors import CORSMiddleware

# --- CONFIGURATION ---
# Get the project root directory (works both locally and on Render)
CURRENT_FILE_DIR = os.path.dirname(os.path.abspath(__file__))  # src/api
SRC_DIR = os.path.dirname(CURRENT_FILE_DIR)  # src
PROJECT_ROOT = os.path.dirname(SRC_DIR)  # project root
MODEL_DIR = os.path.join(SRC_DIR, 'models', 'saved_models')

# Debug: Print paths on startup
print(f"[DEBUG] Current file: {os.path.abspath(__file__)}")
print(f"[DEBUG] SRC_DIR: {SRC_DIR}")
print(f"[DEBUG] MODEL_DIR: {MODEL_DIR}")
print(f"[DEBUG] MODEL_DIR exists: {os.path.exists(MODEL_DIR)}")
if os.path.exists(MODEL_DIR):
    print(f"[DEBUG] MODEL_DIR contents: {os.listdir(MODEL_DIR)}")

# 1. WHITELIST CONFIGURATION (Strictly trusted domains only)
# These are root domains - subdomains will also be trusted (e.g., gemini.google.com)
WHITELIST_ROOT_DOMAINS = {
    # Global Tech Giants
    "google.com",
    "microsoft.com",
    "facebook.com",
    "youtube.com",
    "github.com",
    "amazon.com",
    "stackoverflow.com",
    "chatgpt.com",
    "openai.com",
    "apple.com",
    "netflix.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    "reddit.com",
    "wikipedia.org",
    "discord.com",
    "spotify.com",
    "zoom.us",
    "dropbox.com",
    
    # Vietnamese trusted sites
    "vnexpress.net",
    "tuoitre.vn",
    "thanhnien.vn",
    "dantri.com.vn",
    "vietnamnet.vn",
    "shopee.vn",
    "tiki.vn",
    "lazada.vn",
    "sendo.vn",
    "momo.vn",
    "vietcombank.com.vn",
    "techcombank.com.vn",
    "vietinbank.vn",
    "bidv.com.vn",
    "fpt.com.vn",
    "viettel.vn",
    "vingroup.net"
}

def is_whitelisted(domain: str) -> bool:
    """Check if domain or its parent domain is in whitelist."""
    domain = domain.lower()
    # Exact match
    if domain in WHITELIST_ROOT_DOMAINS:
        return True
    # Check if it's a subdomain of a whitelisted domain
    for trusted in WHITELIST_ROOT_DOMAINS:
        if domain.endswith('.' + trusted):
            return True
    return False

# --- INITIALIZE API ---
app = FastAPI(title="Phishing Detection System API", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- GLOBAL MODEL STORAGE ---
models = {
    "rf": None,
    "yolo": None,
    "bert": None,
    "bert_tokenizer": None
}

# --- HELPER: EXTRACT URL FEATURES (21 FEATURES) ---
def extract_url_features(url):
    """
    Extracts exactly 21 features to match the trained Random Forest model.
    """
    try:
        url = str(url).strip()
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        # Helper to check IP
        def is_ip_address(d):
            try:
                ipaddress.ip_address(d)
                return 1
            except:
                return 0

        # Helper to count special chars
        def count_special_chars(u):
            return len(re.findall(r'[!@#$%^&*(),?":{}|<>]', u))

        # Fix: Ignore '://' to avoid miscounting slashes in protocol
        url_for_counting = url.replace("://", "")

        features = [
            # 1. Length Features (3)
            len(url),
            len(domain),
            len(path),
            
            # 2. Character Counts (9)
            url.count('@'),
            url.count('-'),
            url.count('.'),
            url_for_counting.count('/'), # Uses the fixed variable
            url.count('?'),       
            url.count('='),       
            url.count('http'),
            url.count('www'),     
            count_special_chars(url),
            
            # 3. Binary Features (2)
            1 if parsed.scheme == 'https' else 0,
            is_ip_address(domain),
            
            # 4. Phishing Keywords (7)
            1 if 'login' in url.lower() else 0,
            1 if 'secure' in url.lower() else 0,
            1 if 'account' in url.lower() else 0,
            1 if 'verify' in url.lower() else 0,
            1 if 'signin' in url.lower() else 0,
            1 if 'bank' in url.lower() else 0,
            1 if 'confirm' in url.lower() else 0
        ]
        
        return features
        
    except Exception as e:
        print(f"Error extracting URL features: {e}")
        return [0] * 21

# --- STARTUP EVENT: LOAD MODELS ---
@app.on_event("startup")
async def load_models():
    print("\n>>> [SYSTEM] Starting Server and loading Models...")
    
    # 1. Load Random Forest (URL)
    rf_path = os.path.join(MODEL_DIR, 'url_random_forest.pkl')
    if os.path.exists(rf_path):
        models["rf"] = joblib.load(rf_path)
        print(f"[OK] URL Model Loaded: {rf_path}")
    else:
        print(f"[ERROR] URL Model NOT FOUND at: {rf_path}")

    # 2. Load YOLOv8 (Image)
    yolo_path = os.path.join(MODEL_DIR, 'yolo_logo_detector.pt')
    if os.path.exists(yolo_path):
        models["yolo"] = YOLO(yolo_path)
        print(f"[OK] [CV Model] Loaded: {yolo_path}")
    else:
        print(f"[ERROR] [CV Model] NOT FOUND at: {yolo_path}")

    # 3. Load BERT (Text)
    bert_path = os.path.join(MODEL_DIR, 'bert_phishing')
    if os.path.exists(bert_path):
        try:
            models["bert_tokenizer"] = BertTokenizer.from_pretrained(bert_path)
            models["bert"] = BertForSequenceClassification.from_pretrained(bert_path)
            print(f"[OK] [NLP Model] Loaded: {bert_path}")
        except Exception as e:
            print(f"[ERROR] [NLP Model] Error loading: {e}")
    else:
        print(f"[ERROR] [NLP Model] NOT FOUND at: {bert_path}")

# --- REQUEST BODY ---
class ScanRequest(BaseModel):
    url: str
    html_content: str = ""       
    screenshot_base64: str = ""  

# --- MAIN ENDPOINT ---
@app.post("/predict")
async def predict(request: ScanRequest):
    print(f"\n[REQUEST] Analyzing: {request.url}")
    
    # Debug: Log what data we received
    html_len = len(request.html_content) if request.html_content else 0
    screenshot_len = len(request.screenshot_base64) if request.screenshot_base64 else 0
    print(f"   [DEBUG] HTML length: {html_len} chars")
    print(f"   [DEBUG] Screenshot length: {screenshot_len} chars")
    print(f"   [DEBUG] Models loaded - RF: {models['rf'] is not None}, BERT: {models['bert'] is not None}, YOLO: {models['yolo'] is not None}")
    
    # --- STEP 0: WHITELIST CHECK (Bypass AI) ---
    try:
        parsed_uri = urlparse(request.url)
        domain = parsed_uri.netloc.lower()
        
        if is_whitelisted(domain):
            print(f"   [WHITELIST] Trusted Domain detected: {domain}")
            return {
                "url": request.url,
                "final_verdict": "SAFE",
                "confidence": 1.0, 
                "details": {
                    "url_score": 0,
                    "text_score": 0,
                    "logo_detected": [],
                    "modules_run": ["WHITELIST_PASSED"]
                }
            }
    except Exception as e:
        print(f"Whitelist check error: {e}")

    # --- INITIALIZE RESPONSE ---
    response = {
        "url": request.url,
        "final_verdict": "SAFE",
        "confidence": 0.0,
        "details": {
            "url_score": 0,
            "text_score": 0,
            "logo_detected": [],
            "modules_run": []
        }
    }
    
    # VOTING LOGIC WITH CRITICAL OVERRIDE
    # Standard Rule: Need at least 2 points to flag as PHISHING.
    # Override Rule: If URL Score > 0.99, flag as PHISHING immediately (Catches blocked pages/IPFS).
    
    total_score = 0 

    # === 1. URL ANALYSIS (Weight: 1) ===
    if models["rf"]:
        try:
            feats = extract_url_features(request.url)
            input_feats = [feats] 
            prob = models["rf"].predict_proba(input_feats)[0][1]
            
            response["details"]["url_score"] = float(prob)
            response["details"]["modules_run"].append("URL")
            
            # Add point if suspicious (> 0.6)
            if prob > 0.6:
                print(f"   [WARN] [URL] Suspicious URL Structure (Score: {prob:.4f}) -> +1 Point")
                total_score += 1
        except Exception as e:
            print(f"   [ERROR] [URL] Error: {e}")

    # === 2. TEXT ANALYSIS (Weight: 1) ===
    if models["bert"] and len(request.html_content) > 50:
        try:
            inputs = models["bert_tokenizer"](
                request.html_content, return_tensors="pt", truncation=True, max_length=512
            )
            with torch.no_grad():
                outputs = models["bert"](**inputs)
            
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            phishing_prob = probs[0][1].item()
            
            response["details"]["text_score"] = float(phishing_prob)
            response["details"]["modules_run"].append("TEXT")
            
            # High threshold (0.85) to avoid false positives on news/blogs
            if phishing_prob > 0.85: 
                print(f"   [WARN] [BERT] Phishing Content Detected (Score: {phishing_prob:.4f}) -> +1 Point")
                total_score += 1
        except Exception as e:
            print(f"   [ERROR] [BERT] Error: {e}")

    # === 3. IMAGE ANALYSIS (Weight: 1) ===
    if models["yolo"] and len(request.screenshot_base64) > 100:
        try:
            img_str = request.screenshot_base64
            if ',' in img_str: img_str = img_str.split(',')[1]
            
            image_data = base64.b64decode(img_str)
            image = Image.open(io.BytesIO(image_data))
            
            results = models["yolo"](image, verbose=False)
            response["details"]["modules_run"].append("IMAGE")
            
            detected_logos = []
            for result in results:
                for box in result.boxes:
                    cls_id = int(box.cls[0])
                    conf = float(box.conf[0])
                    class_name = models["yolo"].names[cls_id]
                    
                    if conf > 0.5: 
                        detected_logos.append(class_name)
            
            detected_logos = list(set(detected_logos))
            response["details"]["logo_detected"] = detected_logos
            
            if len(detected_logos) > 0:
                print(f"   [WARN] [YOLO] Logo detected: {detected_logos} -> +1 Point")
                total_score += 1
                    
        except Exception as e:
            print(f"   [ERROR] [YOLO] Error: {e}")

    # === FINAL VERDICT LOGIC ===
    print(f"[SCORING] Total Risk Points: {total_score}/3")
    
    url_prob = response["details"]["url_score"]

    # LOGIC:
    # 1. If Total Score >= 2 -> PHISHING (Consensus from multiple models)
    # 2. CRITICAL OVERRIDE: If URL Score > 0.65 -> PHISHING (Moderate-high risk)
    # 3. Suspicious patterns: TLD, random subdomain, hyphenated domains
    
    # Check for suspicious TLDs commonly used in phishing
    suspicious_tlds = {'.cfd', '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', 
                       '.pw', '.cc', '.su', '.buzz', '.rest', '.icu', '.cam', '.info'}
    parsed_url = urlparse(request.url)
    domain = parsed_url.netloc.lower()
    has_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)
    
    # Check for random-looking subdomain (long alphanumeric strings)
    import re
    has_random_subdomain = bool(re.search(r'[a-z0-9]{10,}\.', domain))
    
    # Check for hyphenated domain names (common in phishing: "paypal-secure.com")
    # Exclude www- prefix
    domain_without_www = domain.replace('www.', '')
    domain_parts = domain_without_www.split('.')
    main_domain = domain_parts[0] if len(domain_parts) > 0 else ''
    has_suspicious_hyphen = '-' in main_domain and len(main_domain) > 5
    
    # Check for brand name impersonation patterns
    brand_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 
                      'confirm', 'bank', 'paypal', 'microsoft', 'apple', 'amazon', 
                      'netflix', 'support', 'service', 'billing', 'invoice']
    has_brand_keyword = any(kw in domain.lower() for kw in brand_keywords)
    
    if total_score >= 2:
        response["final_verdict"] = "PHISHING"
        response["confidence"] = 0.95
        
    elif url_prob > 0.90:  # Very high threshold - only flag extremely suspicious URLs
        print(f"   [CRITICAL] Very High URL Risk Score ({url_prob:.4f}). Override to PHISHING.")
        response["final_verdict"] = "PHISHING"
        response["confidence"] = 0.90
        
    elif has_suspicious_tld and url_prob > 0.6:
        print(f"   [CRITICAL] Suspicious TLD detected with moderate risk. Override to PHISHING.")
        response["final_verdict"] = "PHISHING"
        response["confidence"] = 0.85
        
    elif has_suspicious_hyphen and url_prob > 0.6:
        print(f"   [CRITICAL] Suspicious hyphenated domain detected. Override to PHISHING.")
        response["final_verdict"] = "PHISHING"
        response["confidence"] = 0.80
        
    elif has_random_subdomain and url_prob > 0.5:
        print(f"   [CRITICAL] Random subdomain pattern detected. Override to PHISHING.")
        response["final_verdict"] = "PHISHING"
        response["confidence"] = 0.85
        
    else:
        response["final_verdict"] = "SAFE"
        # If score is 1 (ambiguous), lower confidence. If 0, high confidence.
        response["confidence"] = 0.45 if total_score == 1 else 0.9 
    
    print(f"[RESULT] Verdict: {response['final_verdict']}")
    return response