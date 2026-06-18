"""
Phishing Detection System API — Entry Point
=============================================
FastAPI application with OOP-based multi-model phishing analysis.

Architecture (4 Pillars of OOP):
    Abstraction:   BaseAnalyzer ABC defines the analysis contract
    Inheritance:   URLAnalyzer, TextAnalyzer, ImageAnalyzer extend BaseAnalyzer
    Polymorphism:  predict() iterates list[BaseAnalyzer] calling analyze()
                   TextAnalyzer uses BaseInferenceBackend (ONNX / PyTorch)
    Encapsulation: Each class hides its model state, thresholds, and logic

Run: uvicorn src.api.main:app --host 0.0.0.0 --port 7860
"""
import os
import logging
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .schemas import ScanRequest, ScanResponse, AnalysisDetails, AnalysisReason
from .config import WhitelistConfig, BrandDomainConfig
from .analyzers.base import BaseAnalyzer
from .analyzers.url_analyzer import URLAnalyzer
from .analyzers.text_analyzer import TextAnalyzer
from .analyzers.image_analyzer import ImageAnalyzer
from .verdict import VerdictEngine

# --- LOGGING SETUP (replaces 40+ print() statements) ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
CURRENT_FILE_DIR = os.path.dirname(os.path.abspath(__file__))  # src/api
SRC_DIR = os.path.dirname(CURRENT_FILE_DIR)                    # src
MODEL_DIR = os.path.join(SRC_DIR, "models", "saved_models")

# --- GLOBAL INSTANCES ---
whitelist = WhitelistConfig()
brand_config = BrandDomainConfig()
verdict_engine = VerdictEngine()
analyzers: list[BaseAnalyzer] = []  # Polymorphic list of analyzers


# --- LIFESPAN (replaces deprecated @app.on_event("startup")) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load models on startup, cleanup on shutdown."""
    logger.info(">>> [SYSTEM] Starting Server and loading Models...")
    logger.info(f"MODEL_DIR: {MODEL_DIR}")
    logger.info(f"MODEL_DIR exists: {os.path.exists(MODEL_DIR)}")
    if os.path.exists(MODEL_DIR):
        logger.info(f"MODEL_DIR contents: {os.listdir(MODEL_DIR)}")

    # Initialize analyzers — all share the BaseAnalyzer interface (Polymorphism)
    _all_analyzers: list[BaseAnalyzer] = [
        URLAnalyzer(),
        TextAnalyzer(),
        ImageAnalyzer(brand_config),
    ]

    for analyzer in _all_analyzers:
        analyzer.load_model(MODEL_DIR)
        if analyzer.is_available:
            analyzers.append(analyzer)
            logger.info(f"[OK] {analyzer.name} analyzer ready")
        else:
            logger.warning(f"[SKIP] {analyzer.name} analyzer not available")

    logger.info(f">>> [SYSTEM] {len(analyzers)}/{len(_all_analyzers)} analyzers loaded")

    yield  # Application runs here

    analyzers.clear()
    logger.info(">>> [SYSTEM] Server shutting down, resources cleaned up")


# --- INITIALIZE API ---
app = FastAPI(
    title="Phishing Detection System API",
    version="2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # Development mode — restrict in production
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- ENDPOINTS ---

@app.post("/predict", response_model=ScanResponse, response_model_exclude_none=True)
def predict(request: ScanRequest):
    """Main phishing detection endpoint.

    Uses sync def (not async) to avoid blocking the event loop
    with CPU-bound ML inference operations.

    Pipeline:
        1. Whitelist check → bypass AI if trusted domain
        2. Run all analyzers (Polymorphism: BaseAnalyzer.analyze())
        3. Compute verdict via VerdictEngine
    """
    logger.info(f"[REQUEST] Analyzing: {request.url}")
    logger.debug(
        f"  HTML length: {len(request.html_content)} chars | "
        f"Screenshot length: {len(request.screenshot_base64)} chars"
    )
    logger.debug(
        f"  Analyzers loaded: {[a.name for a in analyzers]}"
    )

    # --- STEP 0: WHITELIST CHECK (bypass AI) ---
    try:
        parsed_uri = urlparse(request.url)
        domain = parsed_uri.netloc.lower()

        if whitelist.is_whitelisted(domain):
            logger.info(f"[WHITELIST] Trusted Domain detected: {domain}")
            return ScanResponse(
                url=request.url,
                final_verdict="SAFE",
                confidence=1.0,
                details=AnalysisDetails(
                    modules_run=["WHITELIST_PASSED"],
                    reasons=[AnalysisReason(
                        message=f"{domain} is a verified trusted domain",
                        type="safe",
                    )],
                ),
            )
    except Exception as e:
        logger.error(f"Whitelist check error: {e}")

    # --- STEP 1: RUN ALL ANALYZERS (Polymorphism) ---
    # Each analyzer is a BaseAnalyzer — we call analyze() without knowing
    # the concrete type (URLAnalyzer, TextAnalyzer, or ImageAnalyzer).
    results = {}
    for analyzer in analyzers:
        try:
            result = analyzer.analyze(request)
            if result is not None:
                results[analyzer.name] = result
        except Exception as e:
            logger.error(f"[{analyzer.name}] Analysis failed: {e}", exc_info=True)

    # --- STEP 2: COMPUTE VERDICT ---
    return verdict_engine.compute_verdict(request.url, results)


@app.get("/health")
def health_check():
    """Health check endpoint for monitoring and deployment readiness."""
    return {
        "status": "healthy",
        "analyzers": {a.name: a.is_available for a in analyzers},
        "total_analyzers": len(analyzers),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=port)