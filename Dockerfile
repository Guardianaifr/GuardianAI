# Use an official lightweight Python image.
# python:3.9-slim is a good balance of size and compatibility.
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Prevent Python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
# Prevent Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1

# Install system dependencies required for building some python packages
# (e.g., psutil often needsgcc)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install spaCy model for Presidio (Natural Language Processing)
# Using sm (small) model for cloud deployment to save memory/space
# and prevent build timeouts on platforms like Railway.
RUN python -m spacy download en_core_web_sm

# Copy the rest of the application
COPY . .

# Exposure ports
# 8081: GuardianAI Proxy
# 8501: Streamlit Dashboard
EXPOSE 8081 8501

# Define environment variables (Can be overridden by docker-compose)
ENV PORT=8081
ENV HOST=0.0.0.0

# Create a startup script
RUN echo '#!/bin/bash\n\
    # Database initialization is handled by main.py\n\
    echo "🚀 Starting GuardianAI Backend on port ${PORT:-8081}..."\n\
    uvicorn backend.main:app --host 0.0.0.0 --port "${PORT:-8081}"\n\
    ' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
