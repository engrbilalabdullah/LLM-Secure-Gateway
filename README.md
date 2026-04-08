# Secure Gateway for LLM Applications 🛡️

**Course:** Artificial Intelligence (CSC 262) - Lab Mid Project  
**Author:** Muhammad Bilal Abdullah  
**Registration:** FA24-BCS-081  
**Institution:** COMSATS University Islamabad, Wah Campus  
**Instructor:** Miss Tooba Tehreem  

## Project Overview
This project is a modular security middleware built with **Python Flask** and **Vanilla JS/HTML**. It sits between end-users and Large Language Models (LLMs) to detect malicious prompt injections and anonymize Personally Identifiable Information (PII) before the data reaches the AI.

### Core Features
1. **Prompt Injection Detection:** A mathematically normalized, weighted scoring mechanism that detects jailbreaks, system prompt extractions, and DAN mode attempts. Includes Confidence Calibration for multi-vector attacks.
2. **PII Anonymization:** Custom integration of **Microsoft Presidio** to detect and mask:
   - Pakistani Phone Numbers (`+92` / `03xx`)
   - COMSATS Student IDs (`FA24-BCS-081` format)
   - OpenAI API Keys (`sk-...`)
3. **Composite Entity Detection:** Flags high-risk requests if multiple identifiers (e.g., ID + Phone) are found in the same prompt.
4. **Configurable Thresholds:** Dynamic frontend sliders to adjust the strictness (Block/Mask/Allow) of the security policy.

## File Structure
- `main.py` - The Flask API gateway and routing logic.
- `injection_detector.py` - Scoring algorithm for detecting malicious intents.
- `pii_handler.py` - Microsoft Presidio custom recognizers and anonymization engine.
- `index.html` - The asynchronous frontend dashboard.

## Installation & Setup (Reproducibility)

Follow these steps to run the gateway locally:

### 1. Install Dependencies
```bash
pip install flask flask-cors presidio-analyzer presidio-anonymizer
