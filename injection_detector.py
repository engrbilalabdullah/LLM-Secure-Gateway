# Developed by: Muhammad Bilal Abdullah (FA24-BCS-081)
# Project: Secure Gateway for LLM (CSC 262 - Lab Mid)

import time

def check_prompt_injection(user_text, threshold=60):
    start_time = time.time()
    text = user_text.lower()
    
    # Common attack patterns (Jailbreaks & Injections)
    attack_library = {
        "ignore all previous": 40,
        "jailbreak": 50,
        "system prompt": 35,
        "forget everything": 30,
        "do anything now": 45,
        "dan mode": 50,
        "bypass filter": 40
    }
    
    risk_score = 0
    flags = []
    
    for pattern, weight in attack_library.items():
        if pattern in text:
            # Simple scoring mechanism [cite: 15]
            risk_score += weight
            flags.append(pattern.upper())
            
    # Confidence Calibration: Agar multiple flags hon toh risk barh jata hai
    if len(flags) > 1:
        risk_score += 10 

    # Policy Decision [cite: 17]
    if risk_score >= threshold:
        decision = "BLOCK"
        reason = f"Security Violation: Risk score {risk_score} exceeds threshold {threshold}."
    elif risk_score > (threshold / 2):
        decision = "MASK"
        reason = "Potential threat detected. Proceeding with caution."
    else:
        decision = "ALLOW"
        reason = "Input verified as safe."
        
    latency = round((time.time() - start_time) * 1000, 2)
        
    return {
        "score": min(risk_score, 100),
        "decision": decision,
        "reason": reason,
        "flags": flags,
        "latency_ms": latency
    }