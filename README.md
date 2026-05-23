# Phishing Attack Detection System

## 1. Project Overview

A highly sophisticated, multi-modal machine learning system designed to detect phishing websites in real-time. By leveraging a combination of structural heuristics, Natural Language Processing (NLP), and Computer Vision (CV), the system accurately classifies malicious domains that attempt to impersonate legitimate services. Unlike traditional blacklist-based approaches, this system dynamically evaluates the intent and composition of a webpage.

## 2. System Architecture

The architecture follows a distributed client-server model:

- **Frontend (Browser Extension)**: Acts as the data extraction layer. It captures the current active tab's URL, parses the HTML DOM content, and renders a viewport screenshot of the loaded webpage. This payload is transmitted securely to the backend.
- **Backend (FastAPI)**: A high-performance, asynchronous API that orchestrates the inference of three independent deep learning and machine learning models. It aggregates their predictions using a deterministic rule engine and a weighted voting mechanism, returning a final risk assessment to the client.

## 3. Technology Stack

- **API Engine**: FastAPI, Uvicorn, Python 3.10+
- **Machine Learning**: PyTorch, Ultralytics, HuggingFace Transformers, XGBoost, Scikit-learn
- **Data Engineering**: Pandas, NumPy, OpenCV, Pillow
- **Frontend Development**: Vanilla JavaScript, Chrome Extension APIs, HTML5, CSS3

## 4. Multi-Modal Verification Pipeline

The core detection engine relies on a 3-pillar verification method.

### 4.1. URL Structural Analysis (XGBoost)

- **Role**: Analyzes the lexical and structural features of the URL string.
- **Features Extracted**: Extracts over 80 distinct features including domain length, presence of hyphens, frequency of special characters, subdomain entropy, TLD reputation, and the occurrence of known phishing-associated keywords within the URI path.
- **Model**: XGBoost Classifier.
- **Rationale**: XGBoost provides exceptional performance on structured tabular data, fast inference times, and robust handling of non-linear feature relationships without the computational overhead of deep neural networks.
- **Performance Metrics**:
  - Train Accuracy: 98.28%
  - Validation Accuracy: 96.32%
  - Test Accuracy: 96.63%
- **Threshold Optimization**: Employs dynamic threshold tuning (maximizing the F1-score via the Precision-Recall curve) rather than a static 0.5 decision boundary to achieve an optimal balance between Precision and Recall.

### 4.2. Semantic Text Analysis (XLM-RoBERTa)

- **Role**: Parses and comprehends the visible DOM text to identify social engineering tactics, such as urgency markers, fake login prompts, and account suspension threats.
- **Model**: `xlm-roberta-base` (Fine-tuned on a custom multilingual corpus).
- **Rationale**: Standard BERT models inherently struggle with linguistic diversity. XLM-RoBERTa provides state-of-the-art cross-lingual representations, making it highly effective at detecting phishing templates in both English and Vietnamese without requiring computationally expensive translation pipelines.
- **Performance Metrics**:
  - Test Accuracy: 92.54%
- **Inference Strategy**: Tokenizes HTML text using a maximum sequence length of 512 tokens. To mitigate false positives on legitimate news platforms and technical blogs, a strict confidence threshold of 0.85 is enforced before classifying the semantic content as malicious.

### 4.3. Visual Impersonation Detection (YOLO26)

- **Role**: Analyzes viewport screenshots to detect the unauthorized presence of corporate logos, which is a primary indicator of brand impersonation.
- **Model**: YOLO26 Nano (`yolo26n_logo_detector.pt`). Built upon the Ultralytics architecture and custom-trained to detect 31 distinct brand classes, encompassing global tech giants and local financial institutions.
- **Dataset Engineering**: Trained on a highly curated dataset. Applied offline augmentation techniques (rotations, HSV adjustments, Gaussian noise, blurring) to synthesize 5,000 diverse training samples from 426 original source images. Implemented strict 80/10/10 stratified dataset splitting and automated ghost-class purging prior to training.
- **Inference Pipeline**:
  - **Dynamic Cropping**: Recognizing that critical brand identifiers reside at the top of a webpage, screenshots are automatically cropped to the top 640x640 pixel region.
  - **Scale Matching**: Images are resized using Lanczos resampling to exactly 640 pixels in width, preserving the aspect ratio. This perfectly aligns the API inference input with the training data distribution.
  - **Confidence Calibration**: A strict confidence threshold of 0.45 is applied to bounding box predictions to filter out background noise, artifacts, and abstract geometric shapes.

## 5. Aggregation and Cross-Referencing Logic

To achieve high precision, the system utilizes an internal deterministic rule engine to cross-reference model outputs:

1. **Brand-to-Domain Mapping**: When YOLO26 detects a logo (e.g., "PayPal"), the system queries the internal `BRAND_DOMAIN_MAP` dictionary.
2. **Evaluation Protocol**:
   - If the detected brand matches the parsed `netloc` (e.g., `paypal.com`), the detection is classified as a legitimate, authorized use of the logo.
   - If a recognized brand is detected on a completely unrelated, obfuscated, or suspicious domain, the system records a high-severity mismatch.
   - If a brand is detected but does not exist in the mapping dictionary, it returns an `UNKNOWN` state to prevent erratic false positive logging.
3. **Voting Mechanism**: Each distinct analytical module contributes to a `total_score`. A domain is only classified as `PHISHING` if it accumulates sufficient points across multiple independent modalities (e.g., a suspicious URL structure combined with a mismatched corporate logo). This architectural redundancy drastically reduces the False Positive Rate (FPR) while maintaining high sensitivity to sophisticated attacks.
