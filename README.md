<div align="center">

# Real-Time Phishing Detection System

### Multi-Modal AI · XGBoost · XLM-RoBERTa · YOLO26 · ONNX

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)](https://pytorch.org)

A production-ready, multi-modal phishing detection system that combines **URL analysis**, **NLP content understanding**, and **computer vision** into a unified real-time pipeline — deployed as a browser extension + FastAPI backend.

<img width="367" height="556" alt="Extension Preview" src="https://github.com/user-attachments/assets/501e8bb6-891f-40ee-b40e-cc1e7ef96f76" />

</div>

---

## Table of Contents

- [Overview](#-overview)
- [Key Results](#-key-results)
- [System Architecture](#-system-architecture)
- [Detection Pipeline](#-detection-pipeline)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [API Usage](#-api-usage)
- [Citation](#-citation)

---

## Overview

Traditional blacklist-based phishing detection (e.g., Google Safe Browsing, PhishTank) suffers from a critical **temporal lag** of 4–24 hours — while the median lifespan of a phishing site is only 15–24 hours. This system solves that problem with **real-time, content-aware detection** using three independent AI models that analyze **what a page looks like, what it says, and where it lives**.

### Why Multi-Modal?

| Attack Vector                    | Single-Model Weakness                 | Our Solution                                  |
| -------------------------------- | ------------------------------------- | --------------------------------------------- |
| Typosquatted URL on a clean page | Text model sees nothing suspicious    | URL model catches structural anomalies        |
| Perfect URL but fake login form  | URL model sees nothing suspicious     | Text model detects phishing language patterns |
| Cloned brand identity            | Both URL and text may look legitimate | Vision model detects logo + domain mismatch   |

---

## Key Results

### Individual Model Performance

| Model                       | Task                  | Accuracy | Recall |  AUC   | Dataset                  |
| :-------------------------- | :-------------------- | :------: | :----: | :----: | :----------------------- |
| **XGBoost**                 | URL Analysis          |  96.63%  | 98.30% | 99.54% | 27,016 URLs              |
| **XLM-RoBERTa** (ONNX INT8) | HTML Content Analysis |  96.68%  | 97.50% | 99.33% | 45,373 HTML pages        |
| **YOLO26 Nano**             | Logo Detection        |    —     | 91.00% |   —    | 5,000 images (31 brands) |

### System-Level Performance

| Metric                               | Value       |
| :----------------------------------- | :---------- |
| System Accuracy (Voting)             | **96.67%**  |
| False Positive Rate (Tranco Top 100) | **1.0%**    |
| Full Pipeline Latency (CPU)          | **186 ms**  |
| Aggregate Memory Footprint           | **~273 MB** |

### End-to-End Latency Breakdown (100 requests, CPU-only)

| Scenario                            | Min (ms) | Mean (ms) | Max (ms) | Std (ms) |
| :---------------------------------- | :------: | :-------: | :------: | :------: |
| Whitelist bypass                    |    2     |     6     |    30    |    6     |
| URL model only                      |    53    |    64     |   146    |    11    |
| URL + text models                   |    98    |    140    |   646    |    57    |
| Full pipeline (URL + text + vision) |   125    |    186    |   391    |    44    |

---

## System Architecture

```
┌─────────────────────────────┐
│    Browser Extension        │
│  (Manifest V3 / Chromium)   │
│                             │
│  • Captures active tab URL  │
│  • Extracts HTML DOM        │
│  • Takes viewport screenshot│
└────────────┬────────────────┘
             │ POST /predict
             ▼
┌─────────────────────────────────────────────┐
│           FastAPI + Uvicorn Backend         │
│                                             │
│  ┌──────────┐ ┌───────────┐ ┌────────────┐  │
│  │ XGBoost  │ │ XLM-R     │ │ YOLO26     │  │
│  │ URL      │ │ ONNX INT8 │ │ Nano       │  │
│  │ (1.8 MB) │ │ (266 MB)  │ │ (5.2 MB)   │  │
│  └────┬─────┘ └─────┬─────┘ └─────┬──────┘  │
│       │             │             │         │
│       ▼             ▼             ▼         │
│  ┌─────────────────────────────────────┐    │
│  │   Cross-Referencing Voting Engine   │    │
│  │  + Brand-Domain Consistency Check   │    │
│  │  + Whitelist Oracle                 │    │
│  └─────────────────────────────────────┘    │
│                    │                        │
│                    ▼                        │
│            Final Verdict:                   │
│         SAFE / PHISHING / WARNING           │
└─────────────────────────────────────────────┘
```

---

## Detection Pipeline

### 1. URL Structural Analysis — XGBoost

Extracts **84 hand-engineered features** from raw URLs including lexical patterns, Shannon entropy, TLD reputation, subdomain structure, and phishing-keyword heuristics. Dynamic threshold optimization via the Precision-Recall curve replaces the naive 0.5 boundary.

### 2. Semantic HTML Analysis — XLM-RoBERTa (ONNX INT8)

Fine-tuned on a **45,373-sample balanced corpus** using a novel **Information-Dense Parsing** strategy that extracts structured HTML signals (`<title>`, `<meta>`, `<form>`, `<input>`, `<a>`, visible text) rather than just visible text alone. This eliminates the "blind spot" for phishing pages with minimal visible content.

Key optimizations:

- **ONNX INT8 Quantization**: Model size reduced from 1.06 GB → **266 MB** (75% reduction)
- **CPU Inference**: ~36 ms per request (4.7× faster than PyTorch baseline)
- **Multilingual**: Natively supports English + Vietnamese without translation

### 3. Visual Brand Detection — YOLO26 Nano

Custom-trained on **5,000 augmented images** covering **31 brand classes** (global tech + local banking). Detects unauthorized brand logos in webpage screenshots and cross-references against a Brand-Domain mapping dictionary to identify impersonation attempts.

### 4. Voting & Aggregation

A deterministic, interpretable voting engine combines all three model outputs:

- Each model contributes a weighted score
- **2-of-3 agreement** required to flag as PHISHING (reduces FPR)
- **Critical override**: URL score > 0.99 triggers immediate PHISHING verdict
- **Brand-domain mismatch** detected by YOLO adds an independent signal

---

## Technology Stack

| Layer                 | Technologies                                                          |
| :-------------------- | :-------------------------------------------------------------------- |
| **API Server**        | FastAPI, Uvicorn, Pydantic                                            |
| **ML / DL**           | PyTorch, ONNX Runtime, HuggingFace Transformers, XGBoost, Ultralytics |
| **Data Processing**   | Pandas, NumPy, BeautifulSoup4, OpenCV, Pillow                         |
| **Browser Extension** | Vanilla JS, Chrome Extension API (Manifest V3), HTML5/CSS3            |
| **Deployment**        | Docker, Render, Gunicorn                                              |

---

## Project Structure

```
phishing-attack-detection/
├── extension/                  # Chromium browser extension (Manifest V3)
│   ├── manifest.json
│   ├── popup.html / popup.js / style.css
│   └── icons/
├── notebook/                   # Training & experiment notebooks
│   ├── train_url.ipynb                  # XGBoost URL model training
│   ├── training_phase_xlmr.ipynb        # XLM-RoBERTa fine-tuning + ONNX export
│   └── training_phase_yolo26n.ipynb     # YOLO26 Nano logo detector training
├── src/
│   ├── api/
│   │   └── main.py             # FastAPI application (inference + voting logic)
│   ├── data_collection/        # Web crawlers (Selenium-based)
│   ├── features/
│   │   └── extract_url_features.py   # 84-feature URL descriptor
│   └── models/
│       └── saved_models/       # Pre-trained weights (gitignored)
├── data/                       # Datasets (gitignored)
├── Dockerfile
├── requirements.txt
└── render.yaml
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/lewisMVP/phishing-attack-detection.git
cd phishing-attack-detection

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Download Pre-trained Models

Place the following model files in `src/models/saved_models/`:

| Model              | File                                      |  Size  |
| :----------------- | :---------------------------------------- | :----: |
| XGBoost            | `url_xgboost.pkl`                         | 1.8 MB |
| XLM-RoBERTa (ONNX) | `xlmr_phishing_onnx/model_quantized.onnx` | 266 MB |
| YOLO26 Nano        | `yolo26n_logo_detector.pt`                | 5.2 MB |

### Run the Server

```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

### Load the Browser Extension

1. Open `chrome://extensions/` in your Chromium-based browser
2. Enable **Developer Mode**
3. Click **Load unpacked** → select the `extension/` folder

---

## API Usage

### Endpoint

```
POST /predict
```

### Request Body

```json
{
  "url": "https://example.com",
  "html_content": "<html>...</html>",
  "screenshot_base64": "iVBORw0KGgo..."
}
```

### Response

```json
{
  "url": "https://example.com",
  "final_verdict": "SAFE",
  "confidence": 0.12,
  "details": {
    "url_score": 0.08,
    "text_score": 0.03,
    "logo_detected": [],
    "logo_mismatch": false,
    "modules_run": ["URL", "TEXT", "VISION"],
    "reasons": [
      { "message": "URL structure appears normal", "type": "safe" },
      { "message": "Site uses HTTPS encryption", "type": "safe" }
    ]
  }
}
```

---

## Citation

If you use this project in your research, please cite:

```bibtex
@thesis{chu2026phishing,
  title     = {Building a Real-Time Phishing Attack Detection System Using Multimodal Artificial Intelligence},
  author    = {Chu, Trung Hung},
  year      = {2026},
  school    = {International School, Vietnam National University},
  type      = {Bachelor's Thesis},
  supervisor = {Mai, Duc Tho}
}
```

---

<div align="center">

**Built with ❤️ by [Lewis Chu](https://github.com/lewisMVP)**

_International School — Vietnam National University, Hanoi_

_Graduation Project · Academic Year 2025–2026_

</div>
