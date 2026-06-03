FROM python:3.10-slim

# Create non-root user (required by Hugging Face Spaces)
RUN useradd -m -u 1000 user

WORKDIR /app

# System dependencies for OpenCV (ultralytics) and Pillow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1-mesa-glx libglib2.0-0 libsm6 libxext6 libxrender-dev \
    && rm -rf /var/lib/apt/lists/*

# Install PyTorch CPU separately (--index-url not supported per-line in requirements.txt)
RUN pip install --no-cache-dir torch torchvision --index-url https://download.pytorch.org/whl/cpu

# Install remaining Python dependencies
COPY requirements.txt .
# Remove torch/torchvision lines (already installed above) then install
RUN sed '/^torch/d' requirements.txt > requirements_clean.txt && \
    pip install --no-cache-dir -r requirements_clean.txt && \
    rm requirements_clean.txt

# Copy only the source code and models needed for the API
COPY src/ ./src/

# Switch to non-root user
USER user

# Hugging Face Spaces requires port 7860
EXPOSE 7860

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "7860"]
