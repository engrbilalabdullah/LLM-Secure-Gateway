# Main Entry Point for AI Lab Mid - Instructor: Tooba Tehreem
# Bilal Abdullah | Registration: FA24-BCS-081

from flask import Flask, request, jsonify
from flask_cors import CORS
import time
from pii_handler import hide_sensitive_data
from injection_detector import check_prompt_injection

app = Flask(__name__)
CORS(app) 

current_config = {
    "block_threshold": 60,
    "mask_threshold": 30
}

@app.route("/", methods=['GET'])
def home():
    return jsonify({
        "student": "Muhammad Bilal Abdullah",
        "reg_no": "FA24-BCS-081",
        "project": "Secure Gateway v1.0"
    })

@app.route("/config", methods=['POST'])
def update_config():
    data = request.get_json()
    
    current_config["block_threshold"] = data.get("injection_block_threshold", 60)
    current_config["mask_threshold"] = data.get("injection_mask_threshold", 30)
    return jsonify({"status": "updated", "config": current_config})

@app.route("/analyze", methods=['POST'])
def analyze():
    overall_start = time.time()
    data = request.get_json()
    prompt = data.get("text", "")

    if not prompt:
        return jsonify({"error": "No input received"}), 400

    inj_data = check_prompt_injection(prompt, threshold=current_config["block_threshold"])

    pii_data = hide_sensitive_data(prompt)

    total_latency = round((time.time() - overall_start) * 1000, 2)

    return jsonify({
        "action": inj_data["decision"], 
        "message": f"{inj_data['decision']} - {inj_data['reason']}",
        "output_text": pii_data["safe_text"],
        "total_latency_ms": total_latency,
        "injection": inj_data,
        "pii": pii_data
    })

if __name__ == "__main__":
    print(f"Server starting for {app.name} - Registration: FA24-BCS-081")
    app.run(debug=True, port=5000)
