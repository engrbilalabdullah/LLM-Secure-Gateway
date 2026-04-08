
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
import time

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()
api_pattern = Pattern(name="api_key", regex="sk-[a-zA-Z0-9]{32,}", score=0.95)
api_rec = PatternRecognizer(supported_entity="API_KEY", patterns=[api_pattern])
analyzer.registry.add_recognizer(api_rec)

phone_pattern = Pattern(name="pk_phone", regex=r"(\+92|0)[3][0-9]{2}-?[0-9]{7}", score=0.85)
phone_rec = PatternRecognizer(supported_entity="PK_PHONE", patterns=[phone_pattern])
analyzer.registry.add_recognizer(phone_rec)

id_pattern = Pattern(name="student_id", regex=r"[A-Z]{2}\d{2}-[A-Z]{3}-\d{3}", score=1.0)
id_rec = PatternRecognizer(supported_entity="STUDENT_ID", patterns=[id_pattern])
analyzer.registry.add_recognizer(id_rec)

def hide_sensitive_data(user_text):
    start_time = time.time()
    entities = ["PERSON", "EMAIL_ADDRESS", "API_KEY", "PK_PHONE", "STUDENT_ID"]
    
    results = analyzer.analyze(text=user_text, entities=entities, language='en')
    
    detected = []
    has_id = False
    has_phone = False

    for res in results:
        entity_name = res.entity_type
        detected.append({
            "entity_type": entity_name,
            "text": user_text[res.start:res.end],
            "score": res.score
        })
        if entity_name == "STUDENT_ID": has_id = True
        if entity_name == "PK_PHONE": has_phone = True

    composite_flags = []
    if has_id and has_phone:
        composite_flags.append("USER_IDENTITY_EXPOSURE")

    anonymized = anonymizer.anonymize(text=user_text, analyzer_results=results)
    latency = round((time.time() - start_time) * 1000, 2)
    
    return {
        "safe_text": anonymized.text,
        "entities": detected,
        "latency_ms": latency,
        "composite_flags": composite_flags
    }
