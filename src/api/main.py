from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import os
import sys
import base64
import io
import torch
import numpy as np
import pandas as pd
from PIL import Image
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from ultralytics import YOLO
from urllib.parse import urlparse
import re
import ipaddress
from fastapi.middleware.cors import CORSMiddleware

# --- Import advanced feature extraction module ---
CURRENT_FILE_DIR_INIT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR_INIT = os.path.dirname(CURRENT_FILE_DIR_INIT)
if SRC_DIR_INIT not in sys.path:
    sys.path.insert(0, SRC_DIR_INIT)
from features.extract_url_features import extract_features

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
    "google",  # .google gTLD is owned by Google
    "microsoft.com",
    "facebook.com",
    "youtube.com",
    "github.com",
    "amazon.com",
    "stackoverflow.com",
    "chatgpt.com",
    "openai.com",
    "claude.ai",
    "perplexity.ai",
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
    "pepsi.com",
    "starbucks.com"
    "coca-colacompany.com"
    "adidas.com"
    "nike.com"
    
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
    #"vietcombank.com.vn",
    "techcombank.com.vn",
    "vietinbank.vn",
    "bidv.com.vn",
    "fpt.com.vn",
    "viettel.vn",
    "vingroup.net"
}

# 2. BRAND-DOMAIN MAPPING (for logo cross-referencing)
# Maps YOLO-detected brand name → legitimate domains for that brand
BRAND_DOMAIN_MAP = {
    # Tech
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "azure.com", "bing.com", "msn.com"],
    "google":    ["google.com", "google.co", "googleapis.com", "gstatic.com", "youtube.com", "gmail.com", "antigravity.google"],
    "apple":     ["apple.com", "icloud.com", "itunes.com"],
    "adobe":     ["adobe.com", "adobelogin.com"],
    "facebook":  ["facebook.com", "fb.com", "meta.com", "messenger.com"],
    "linkedin":  ["linkedin.com"],
    "amazon":    ["amazon.com", "amazon.co", "aws.amazon.com", "amazonservices.com"],
    "netflix":   ["netflix.com"],
    "tiktok":    ["tiktok.com"],
    "instagram": ["instagram.com"],

    # E-commerce / Shipping
    "ebay":      ["ebay.com"],
    "shopee":    ["shopee.com", "shopee.vn", "shopee.co.id", "shopee.ph", "shopee.com.my", "shopee.sg", "shopee.co.th", "shopee.tw"],
    "lazada":    ["lazada.com", "lazada.vn", "lazada.co.id", "lazada.com.ph", "lazada.com.my", "lazada.sg", "lazada.co.th"],
    "tiki":      ["tiki.vn"],
    "dhl":       ["dhl.com"],
    "fedex":     ["fedex.com"],
    "ups":       ["ups.com"],

    # International Finance / Payments
    "paypal":    ["paypal.com"],
    "stripe":    ["stripe.com"],
    "hsbc":      ["hsbc.com", "hsbc.co.uk", "hsbc.com.vn"],
    "citibank":  ["citibank.com", "citi.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "chase":     ["chase.com"],
    "visa":      ["visa.com"],
    "mastercard":["mastercard.com", "mastercard.us"],

    # Vietnamese Finance / Payments
    "momo":      ["momo.vn"],
    "vnpay":     ["vnpay.vn"],
    "zalopay":   ["zalopay.vn"],
    "vietcombank":["vietcombank.com.vn", "vietcombank.com"],
    "techcombank":["techcombank.com.vn", "techcombank.com"],
    "mbbank":    ["mbbank.com.vn", "mb.com.vn"],
    "bidv":      ["bidv.com.vn"],
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

def check_brand_domain_match(brand: str, domain: str) -> str:
    """Check if detected brand matches the website domain. Returns MATCH, MISMATCH, or UNKNOWN."""
    brand_lower = brand.lower()
    domain_lower = domain.lower()
    if brand_lower not in BRAND_DOMAIN_MAP:
        return "UNKNOWN"  # Unknown brand, can't cross-reference
    for legit_domain in BRAND_DOMAIN_MAP[brand_lower]:
        if domain_lower == legit_domain or domain_lower.endswith('.' + legit_domain):
            return "MATCH"
    return "MISMATCH"

def check_brand_content_match(brand: str, html_content: str) -> bool:
    """Check if detected brand name appears in page HTML content."""
    if not html_content:
        return False
    content_lower = html_content.lower()
    brand_lower = brand.lower()
    # Check brand name in content (title, headings, body text)
    return brand_lower in content_lower

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
    "xgb": None,
    "xgb_threshold": 0.5,  # default, will be overridden by saved threshold
    "xgb_feature_names": None,
    "yolo": None,
    "bert": None,
    "bert_tokenizer": None
}

# --- HELPER: EXTRACT URL FEATURES (69 FEATURES via XGBoost module) ---
def extract_url_features_for_api(url: str) -> pd.DataFrame:
    """
    Extracts 69 advanced features for a single URL using the shared extraction module.
    Returns a DataFrame row ready for model prediction.
    """
    try:
        df_input = pd.DataFrame({'url': [str(url).strip()], 'label': [0]})
        df_features = extract_features(df_input)
        # Drop 'url' and 'label' columns, keep only feature columns
        feature_cols = [c for c in df_features.columns if c not in ('url', 'label')]
        return df_features[feature_cols]
    except Exception as e:
        print(f"Error extracting URL features: {e}")
        return None

# --- STARTUP EVENT: LOAD MODELS ---
@app.on_event("startup")
async def load_models():
    print("\n>>> [SYSTEM] Starting Server and loading Models...")
    
    # 1. Load XGBoost (URL) - includes model + optimal threshold
    xgb_path = os.path.join(MODEL_DIR, 'url_xgboost.pkl')
    if os.path.exists(xgb_path):
        model_data = joblib.load(xgb_path)
        models["xgb"] = model_data['model']
        models["xgb_threshold"] = model_data.get('optimal_threshold', 0.5)
        models["xgb_feature_names"] = model_data.get('feature_names', None)
        print(f"[OK] XGBoost URL Model Loaded: {xgb_path}")
        print(f"     Optimal Threshold: {models['xgb_threshold']:.4f}")
        print(f"     Target FPR: < {model_data.get('target_fpr', 'N/A')}")
    else:
        print(f"[ERROR] XGBoost URL Model NOT FOUND at: {xgb_path}")

    # 2. Load YOLO26 (Image — Logo Detection + Cross-Referencing)
    yolo_path = os.path.join(MODEL_DIR, 'yolo26n_logo_detector.pt')
    if os.path.exists(yolo_path):
        models["yolo"] = YOLO(yolo_path)
        print(f"[OK] [CV Model] YOLO26 Loaded: {yolo_path}")
    else:
        print(f"[ERROR] [CV Model] NOT FOUND at: {yolo_path}")

    # 3. Load XLM-RoBERTa (Text)
    xlmr_path = os.path.join(MODEL_DIR, 'xlmr_phishing')
    if os.path.exists(xlmr_path):
        try:
            models["bert_tokenizer"] = AutoTokenizer.from_pretrained(xlmr_path)
            models["bert"] = AutoModelForSequenceClassification.from_pretrained(xlmr_path)
            print(f"[OK] [NLP Model] XLM-RoBERTa Loaded: {xlmr_path}")
        except Exception as e:
            print(f"[ERROR] [NLP Model] Error loading: {e}")
    else:
        print(f"[ERROR] [NLP Model] NOT FOUND at: {xlmr_path}")

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
    print(f"   [DEBUG] Models loaded - XGB: {models['xgb'] is not None}, XLM-RoBERTa: {models['bert'] is not None}, YOLO: {models['yolo'] is not None}")
    
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
                    "logo_mismatch": False,
                    "modules_run": ["WHITELIST_PASSED"],
                    "reasons": [{"message": f"{domain} is a verified trusted domain", "type": "safe"}]
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
            "logo_mismatch": False,
            "modules_run": [],
            "reasons": []
        }
    }
    
    reasons = []  # Collect reasons throughout analysis
    
    # === 0. PROTOCOL CHECK (Informational only, does NOT affect scoring) ===
    parsed_url = urlparse(request.url)
    if parsed_url.scheme != "https":
        print(f"   [WARN] [PROTOCOL] Site does not use HTTPS ({parsed_url.scheme}://)")
        reasons.append({"message": "This site does not use HTTPS encryption. Data sent to this site may not be secure.", "type": "warning"})
    else:
        reasons.append({"message": "Site uses HTTPS encryption", "type": "safe"})
    
    # VOTING LOGIC WITH CRITICAL OVERRIDE
    # Standard Rule: Need at least 2 points to flag as PHISHING.
    # Override Rule: If URL Score > 0.99, flag as PHISHING immediately (Catches blocked pages/IPFS).
    
    total_score = 0 

    # === 1. URL ANALYSIS (Weight: 1) - XGBoost with Custom Threshold ===
    if models["xgb"]:
        try:
            features_df = extract_url_features_for_api(request.url)
            if features_df is not None:
                # Ensure feature columns match training order
                if models["xgb_feature_names"]:
                    features_df = features_df.reindex(columns=models["xgb_feature_names"], fill_value=0)
                
                prob = models["xgb"].predict_proba(features_df)[0][1]
                threshold = models["xgb_threshold"]
                is_phishing = prob >= threshold
                
                response["details"]["url_score"] = float(prob)
                response["details"]["url_threshold"] = float(threshold)
                response["details"]["modules_run"].append("URL")
                
                # Use the trained optimal threshold instead of hardcoded 0.6
                if is_phishing:
                    print(f"   [WARN] [URL-XGB] Phishing detected (Score: {prob:.4f} >= threshold {threshold:.4f}) -> +1 Point")
                    total_score += 1
                    reasons.append({"message": f"URL has suspicious structure (Risk score: {prob:.0%})", "type": "danger"})
                else:
                    print(f"   [INFO] [URL-XGB] Safe (Score: {prob:.4f} < threshold {threshold:.4f})")
                    reasons.append({"message": f"URL structure appears normal (Risk score: {prob:.0%})", "type": "safe"})
        except Exception as e:
            print(f"   [ERROR] [URL-XGB] Error: {e}")

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
                print(f"   [WARN] [XLM-R] Phishing Content Detected (Score: {phishing_prob:.4f}) -> +1 Point")
                total_score += 1
                reasons.append({"message": f"Page content contains phishing patterns (Score: {phishing_prob:.0%})", "type": "danger"})
            else:
                reasons.append({"message": f"Page content appears legitimate (Score: {phishing_prob:.0%})", "type": "safe"})
        except Exception as e:
            print(f"   [ERROR] [XLM-R] Error: {e}")

    # === 3. IMAGE ANALYSIS + LOGO CROSS-REFERENCING ===
    if models["yolo"] and len(request.screenshot_base64) > 100:
        try:
            img_str = request.screenshot_base64
            if ',' in img_str: img_str = img_str.split(',')[1]
            
            image_data = base64.b64decode(img_str)
            image = Image.open(io.BytesIO(image_data))
            
            # --- PRE-RESIZE TO MATCH TRAINING DATA ---
            # Training images trong Roboflow dataset đều có width=640 (ví dụ 640x296).
            # Resize screenshot về width=640 giữ nguyên tỷ lệ để khớp với phân phối training.
            width, height = image.size
            if width != 640:
                new_height = int(height * (640 / width))
                image = image.resize((640, new_height), Image.LANCZOS)
                print(f"   [DEBUG] Resized to match training format: {image.size}")
            
            # Nếu ảnh vẫn quá cao (trang web cuộn dài), cắt lấy phần header
            if image.size[1] > 640:
                image = image.crop((0, 0, 640, 640))
                print(f"   [DEBUG] Cropped height to: {image.size}")
            
            # Đưa vào YOLO
            results = models["yolo"](image, conf=0.45, imgsz=640, verbose=False)
            
            print(f"   [DEBUG] YOLO detections count: {len(results[0].boxes)}")
            response["details"]["modules_run"].append("IMAGE")
            
            detected_logos = []
            for result in results:
                for box in result.boxes:
                    cls_id = int(box.cls[0])
                    conf = float(box.conf[0])
                    class_name = models["yolo"].names[cls_id]
                    
                    print(f"   [DEBUG] YOLO Raw Detection: {class_name} ({conf:.2f})")
                    # Chỉ lấy các logo có độ tin cậy cao (>= 0.45) để tránh False Positives
                    if conf >= 0.45: 
                        detected_logos.append(class_name)
            
            detected_logos = list(set(detected_logos))
            response["details"]["logo_detected"] = detected_logos
            
            # --- LOGO CROSS-REFERENCING ---
            # Check each detected brand against the actual URL domain and page content
            if len(detected_logos) > 0:
                parsed_uri = urlparse(request.url)
                current_domain = parsed_uri.netloc.lower()
                html_content = request.html_content or ""
                
                mismatched_brands = []
                for brand in detected_logos:
                    domain_match_status = check_brand_domain_match(brand, current_domain)
                    content_match = check_brand_content_match(brand, html_content)
                    
                    if domain_match_status == "MATCH":
                        # Logo matches URL → legitimate, no penalty
                        print(f"   [INFO] [YOLO] {brand} logo detected — URL matches ({current_domain})")
                    elif domain_match_status == "MISMATCH":
                        if content_match:
                            # Brand in content but not in URL — suspicious
                            print(f"   [WARN] [YOLO] {brand} logo + content match but URL doesn't match → suspicious")
                            mismatched_brands.append(brand)
                        else:
                            # Logo found but no content mention and URL mismatch
                            print(f"   [WARN] [YOLO] {brand} logo detected but URL ({current_domain}) doesn't match → suspicious")
                            mismatched_brands.append(brand)
                    elif domain_match_status == "UNKNOWN":
                        print(f"   [INFO] [YOLO] {brand} logo detected (brand domain unknown, skipping URL cross-reference)")
                        # If unknown, we don't necessarily penalize by default, unless logic requires it
                
                if mismatched_brands:
                    response["details"]["logo_mismatch"] = True
                    total_score += 1
                    brand_list = ", ".join([b.capitalize() for b in mismatched_brands])
                    reasons.append({"message": f"{brand_list} logo detected but URL is not an official {brand_list} domain", "type": "danger"})
                else:
                    matched_brands = [b for b in detected_logos if check_brand_domain_match(b, current_domain) == "MATCH"]
                    if matched_brands:
                        brand_list = ", ".join([b.capitalize() for b in matched_brands])
                        reasons.append({"message": f"{brand_list} logo detected and matches the website domain", "type": "safe"})
                        print(f"   [INFO] [YOLO] All detected logos match the domain — no penalty")
                    else:
                        brand_list = ", ".join([b.capitalize() for b in detected_logos])
                        reasons.append({"message": f"{brand_list} logo detected (brand domain unknown)", "type": "safe"})
                        print(f"   [INFO] [YOLO] Detected logos have unknown domains — no penalty")
            else:
                print(f"   [INFO] [YOLO] No brand logo detected in screenshot")
                reasons.append({"message": "No brand logo detected in screenshot", "type": "safe"})
                    
        except Exception as e:
            print(f"   [ERROR] [YOLO] Error: {e}")

    # === FINAL VERDICT LOGIC ===
    print(f"[SCORING] Total Risk Points: {total_score}/3")
    
    url_prob = response["details"]["url_score"]

    # LOGIC:
    # 1. If Total Score >= 2 -> PHISHING (Consensus from multiple models)
    # 2. CRITICAL OVERRIDE: If URL Score > 0.90 -> PHISHING
    # 3. Suspicious patterns: TLD, random subdomain, hyphenated domains
    
    # Check for suspicious TLDs commonly used in phishing
    suspicious_tlds = {'.cfd', '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', 
                       '.pw', '.cc', '.su', '.buzz', '.rest', '.icu', '.cam', '.info'}
    parsed_url = urlparse(request.url)
    domain = parsed_url.netloc.lower()
    has_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)
    
    # Check for random-looking subdomain (long alphanumeric strings)
    has_random_subdomain = bool(re.search(r'[a-z0-9]{10,}\.', domain))
    
    # Check for hyphenated domain names (common in phishing: "paypal-secure.com")
    domain_without_www = domain.replace('www.', '')
    domain_parts = domain_without_www.split('.')
    main_domain = domain_parts[0] if len(domain_parts) > 0 else ''
    has_suspicious_hyphen = '-' in main_domain and len(main_domain) > 5
    
    # Check for brand name impersonation patterns
    brand_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 
                      'confirm', 'bank', 'paypal', 'microsoft', 'apple', 'amazon', 
                      'netflix', 'support', 'service', 'billing', 'invoice']
    has_brand_keyword = any(kw in domain.lower() for kw in brand_keywords)
    
    # Add pattern-based reasons
    if has_suspicious_tld:
        tld_match = [tld for tld in suspicious_tlds if domain.endswith(tld)]
        reasons.append({"message": f"Uses suspicious domain extension ({tld_match[0] if tld_match else 'unknown'})", "type": "danger"})
    if has_random_subdomain:
        reasons.append({"message": "URL contains random-looking subdomain pattern", "type": "danger"})
    if has_suspicious_hyphen:
        reasons.append({"message": f"Domain uses suspicious hyphenation ({main_domain})", "type": "danger"})
    if has_brand_keyword:
        matched_kw = [kw for kw in brand_keywords if kw in domain.lower()]
        reasons.append({"message": f"Domain contains brand/action keywords: {', '.join(matched_kw)}", "type": "danger"})
    
    if total_score >= 2:
        response["final_verdict"] = "PHISHING"
        response["confidence"] = 0.95
        
    elif url_prob > 0.90:
        print(f"   [CRITICAL] Very High URL Risk Score ({url_prob:.4f}). Override to PHISHING.")
        response["final_verdict"] = "PHISHING"
        response["confidence"] = 0.90
        reasons.append({"message": f"Extremely high URL risk score ({url_prob:.0%})", "type": "danger"})
        
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
        response["confidence"] = 0.45 if total_score == 1 else 0.9
        if total_score == 0:
            reasons.append({"message": "No threats detected across all analysis modules", "type": "safe"})
    
    # Attach reasons to response
    response["details"]["reasons"] = reasons
    
    print(f"[RESULT] Verdict: {response['final_verdict']} | Reasons: {reasons}")
    return response