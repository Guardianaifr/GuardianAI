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
# using en_core_web_lg for better accuracy
RUN python -m spacy download en_core_web_lg

# Copy the rest of the application
COPY . .

# Exposure ports
# 8081: GuardianAI Proxy
# 8501: Streamlit Dashboard
EXPOSE 8081 8501

# Define environment variables (Can be overridden by docker-compose)
ENV PORT=8081
ENV HOST=0.0.0.0

# Create a startup script to run both services
RUN echo '#!/bin/bash\n\
    # Start the Dashboard in the background\n\
    streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0 &\n\
    \n\
    # Start the GuardianAI Proxy in the foreground\n\
    uvicorn backend.main:app --host 0.0.0.0 --port 8081\n\
    ' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
