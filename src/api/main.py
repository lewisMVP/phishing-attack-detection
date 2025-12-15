import uvicorn
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

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # Points to 'src'
MODEL_DIR = os.path.join(BASE_DIR, 'models', 'saved_models')

# --- INITIALIZE API ---
app = FastAPI(title="Phishing Detection System API", version="1.0")

# --- GLOBAL MODEL STORAGE ---
models = {
    "rf": None,
    "yolo": None,
    "bert": None,
    "bert_tokenizer": None
}

# --- HELPER: EXTRACT URL FEATURES ---
# IMPORTANT: This must match the features used during training (23 features)
def extract_url_features(url):
    try:
        parsed = urlparse(url)
        features = [
            len(url), 
            len(parsed.netloc), 
            len(parsed.path),
            url.count('@'), 
            url.count('-'), 
            url.count('.'),
            url.count('/'), 
            url.count('http'),
            len(re.findall(r'[!@#$%^&*(),?":{}|<>]', url)), # count_special
            1 if parsed.scheme == 'https' else 0,
            0, # is_ip (Placeholder)
            1 if 'login' in url.lower() else 0,
            1 if 'client' in url.lower() else 0,
            1 if 'server' in url.lower() else 0,
            1 if 'verify' in url.lower() else 0,
            1 if 'update' in url.lower() else 0,
            1 if 'account' in url.lower() else 0,
            1 if 'signin' in url.lower() else 0, # Added to match common lists
            1 if 'bank' in url.lower() else 0,
            1 if 'confirm' in url.lower() else 0,
            1 if 'secure' in url.lower() else 0,
            0, 0 # Padding to ensure exactly 23 features
        ]
        return features[:23] 
    except Exception as e:
        print(f"Error extracting URL features: {e}")
        return [0] * 23

# --- STARTUP EVENT: LOAD MODELS ---
@app.on_event("startup")
async def load_models():
    print("\n>>> [SYSTEM] Starting Server and loading Models...")
    
    # 1. Load Random Forest (URL)
    rf_path = os.path.join(MODEL_DIR, 'url_random_forest.pkl')
    if os.path.exists(rf_path):
        models["rf"] = joblib.load(rf_path)
        print(f"✅ https://www.merriam-webster.com/dictionary/model Loaded: {rf_path}")
    else:
        print(f"❌ https://www.merriam-webster.com/dictionary/model NOT FOUND at: {rf_path}")

    # 2. Load YOLOv8 (Image)
    yolo_path = os.path.join(MODEL_DIR, 'yolo_logo_detector.pt')
    if os.path.exists(yolo_path):
        models["yolo"] = YOLO(yolo_path)
        print(f"✅ [CV Model] Loaded: {yolo_path}")
    else:
        print(f"❌ [CV Model] NOT FOUND at: {yolo_path}")

    # 3. Load BERT (Text)
    bert_path = os.path.join(MODEL_DIR, 'bert_phishing')
    if os.path.exists(bert_path):
        try:
            models["bert_tokenizer"] = BertTokenizer.from_pretrained(bert_path)
            models["bert"] = BertForSequenceClassification.from_pretrained(bert_path)
            print(f"✅ [NLP Model] Loaded: {bert_path}")
        except Exception as e:
            print(f"❌ [NLP Model] Error loading: {e}")
    else:
        print(f"❌ [NLP Model] NOT FOUND at: {bert_path}")

# --- REQUEST BODY ---
class ScanRequest(BaseModel):
    url: str
    html_content: str = ""       
    screenshot_base64: str = ""  

# --- MAIN ENDPOINT ---
@app.post("/predict")
async def predict(request: ScanRequest):
    print(f"\n🔍 [REQUEST] Analyzing: {request.url}")
    
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
    
    votes = 0 

    # === 1. URL ANALYSIS ===
    if models["rf"]:
        try:
            feats = extract_url_features(request.url)
            is_phishing = models["rf"].predict([feats])[0]
            prob = models["rf"].predict_proba([feats])[0][1]
            
            response["details"]["url_score"] = float(prob)
            response["details"]["modules_run"].append("URL")
            
            if is_phishing == 1:
                print(f"   ⚠️ [URL] Phishing detected (Score: {prob:.4f})")
                votes += 1
        except Exception as e:
            print(f"   ❌ [URL] Error: {e}")

    # === 2. TEXT ANALYSIS (BERT) ===
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
            
            if phishing_prob > 0.7: 
                print(f"   ⚠️ [BERT] Phishing content detected (Score: {phishing_prob:.4f})")
                votes += 1
        except Exception as e:
            print(f"   ❌ [BERT] Error: {e}")

    # === 3. IMAGE ANALYSIS (YOLO) ===
    if models["yolo"] and len(request.screenshot_base64) > 100:
        try:
            # Clean base64 string
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
                    
                    if conf > 0.4: 
                        detected_logos.append(class_name)
            
            response["details"]["logo_detected"] = list(set(detected_logos))
            
            if len(detected_logos) > 0:
                print(f"   ⚠️ [YOLO] Logo detected: {detected_logos}")
                # Simple Logic: If Logo exists AND URL looks weird -> Phishing
                if response["details"]["url_score"] > 0.4:
                    votes += 1
                    
        except Exception as e:
            print(f"   ❌ [YOLO] Error: {e}")

    # === FINAL VERDICT ===
    if votes >= 1:
        response["final_verdict"] = "PHISHING"
        response["confidence"] = 0.9
    
    print(f"🏁 [RESULT] Verdict: {response['final_verdict']}")
    return response