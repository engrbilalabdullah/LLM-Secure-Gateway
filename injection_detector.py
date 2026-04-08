import time

def check_prompt_injection(user_text, threshold=60):
    start_time = time.time()
    text = user_text.lower()

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
           
            risk_score += weight
            flags.append(pattern.upper())
            
   
    if len(flags) > 1:
        risk_score += 10 
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
