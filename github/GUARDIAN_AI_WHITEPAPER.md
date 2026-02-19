# GuardianAI Whitepaper

## Project Summary
GuardianAI is an AI security proxy that protects LLM traffic against prompt injection, sensitive output leakage, abuse patterns, and unsafe runtime behavior.

## Core Security Model
GuardianAI applies layered controls:
1. Input filtering
2. Threat feed matching
3. Base64 obfuscation detection
4. Semantic AI firewall checks
5. Output validation and redaction

## Technology
- Python
- Flask-based proxy runtime
- FastAPI backend API
- Sentence-transformers (when available)
- Presidio + regex fallback for PII handling
- Pytest for automated testing

## Validation Snapshot
- Security and stability validated through benchmark and demo workflows.
- Latest local test status: 61/61 passing.

## Product Direction
GuardianAI focuses on practical, deployable security for AI traffic with clear operator visibility and safe defaults.
