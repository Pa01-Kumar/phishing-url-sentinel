FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    whois \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (UID 1000 required for Hugging Face Spaces & security)
RUN useradd -m -u 1000 user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    PYTHONUNBUFFERED=1

WORKDIR $HOME/app

# Install Python dependencies (PyTorch CPU for fast builds and low memory footprint)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY --chown=user . $HOME/app

# Pre-cache Hugging Face transformer model so container boots in seconds
RUN python -c "from transformers import pipeline; pipeline('text-classification', model='Eason918/malicious-url-detector')"

USER user

# Support Hugging Face Spaces (default 7860) and Render/Railway ($PORT)
ENV PORT=7860
EXPOSE 7860

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-7860}"]
