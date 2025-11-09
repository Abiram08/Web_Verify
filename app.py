from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
from urllib.parse import urlparse, quote
import webbrowser
import os
import requests
import re
import json
import tldextract
import google.generativeai as genai
from datetime import datetime
try:
    import tomllib
except Exception:
    tomllib = None

app = Flask(__name__)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if (not GEMINI_API_KEY or not VIRUSTOTAL_API_KEY) and tomllib is not None:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    secrets_path = os.path.join(base_dir, ".streamlit", "secrets.toml")
    if os.path.exists(secrets_path):
        try:
            with open(secrets_path, "rb") as f:
                secrets = tomllib.load(f)
            GEMINI_API_KEY = GEMINI_API_KEY or secrets.get("GEMINI_API_KEY")
            VIRUSTOTAL_API_KEY = VIRUSTOTAL_API_KEY or secrets.get("VIRUSTOTAL_API_KEY")
        except Exception:
            pass
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
MODEL_PATH = 'model.pkl'
try:
    ml_model = joblib.load(MODEL_PATH)
    print("ML Model loaded")
except Exception as e:
    print(f"ML Model load error: {e}")
    ml_model = None
def extract_ml_features(url):
    parsed_url = urlparse(url)
    domain_name = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query
    features = [
        len(url),
        domain_name.count('.'),
        len(domain_name),
        url.count('/'),
        len(path),
        len(query)
    ]
    return np.array(features).reshape(1, -1)

def get_ml_prediction(url):
    if not ml_model:
        return {"verdict": "Unknown", "confidence": 0, "reason": "ML model not available"}
    try:
        features = extract_ml_features(url)
        prediction = ml_model.predict(features)
        proba = ml_model.predict_proba(features) if hasattr(ml_model, 'predict_proba') else None
        verdict = 'Legitimate' if prediction[0] == 1 else 'Phishing'
        confidence = int(proba[0][prediction[0]] * 100) if proba is not None else 85
        return {"verdict": verdict, "confidence": confidence, "reason": "ML model analyzed URL structure and patterns"}
    except Exception as e:
        return {"verdict": "Unknown", "confidence": 0, "reason": f"ML Error: {str(e)}"}

# -------------------------
# Enhanced Feature Extraction for AI
# -------------------------
def extract_advanced_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    return {
        "url_length": len(url),
        "domain_length": len(parsed.netloc),
        "has_ip": bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc)),
        "num_subdomains": len(ext.subdomain.split('.')) if ext.subdomain else 0,
        "tld": ext.suffix,
        "has_https": parsed.scheme == "https",
        "num_special_chars": sum(url.count(c) for c in ['@', '-', '_', '~']),
        "num_digits": sum(c.isdigit() for c in url),
        "path_depth": parsed.path.count('/'),
        "query_length": len(parsed.query),
        "has_suspicious_keywords": any(kw in url.lower() for kw in ['login','verify','account','update','secure','banking','paypal','ebay'])
    }

# -------------------------
# VirusTotal Integration
# -------------------------
def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return {"available": False, "message": "VirusTotal API key not configured"}
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=10)
        if scan_response.status_code != 200:
            return {"available": False, "message": "VirusTotal scan failed"}
        analysis_id = scan_response.json()['data']['id']
        analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=10)
        if analysis_response.status_code == 200:
            data = analysis_response.json()['data']['attributes']
            stats = data.get('stats', {})
            verdict = "Malicious" if stats.get('malicious',0) > 0 else ("Suspicious" if stats.get('suspicious',0) > 0 else "Safe")
            return {"available": True, "malicious": stats.get('malicious',0), "suspicious": stats.get('suspicious',0), "harmless": stats.get('harmless',0), "undetected": stats.get('undetected',0), "verdict": verdict}
        return {"available": False, "message": "Could not retrieve analysis"}
    except Exception as e:
        return {"available": False, "message": f"Error: {str(e)}"}

# -------------------------
# Gemini AI Analysis
# -------------------------
def analyze_with_gemini(url, features, vt_data, ml_data):
    if not GEMINI_API_KEY:
        return {"available": False, "message": "Gemini API key not configured"}
    try:
        model = genai.GenerativeModel('models/gemini-2.0-flash')
        feature_text = "\n".join([f"  • {k}: {v}" for k, v in features.items()])
        vt_text = f"VirusTotal: {vt_data.get('verdict', 'N/A')} (Malicious: {vt_data.get('malicious', 0)}, Suspicious: {vt_data.get('suspicious', 0)})" if vt_data.get('available') else "VirusTotal: Not available"
        ml_text = f"ML Model: {ml_data.get('verdict', 'Unknown')} ({ml_data.get('confidence', 0)}% confidence)"
        
        prompt = f"""You are an expert cybersecurity analyst specializing in phishing detection and URL threat assessment. 

**URL TO ANALYZE:** {url}

**TECHNICAL FEATURES:**
{feature_text}

**EXTERNAL INTELLIGENCE:**
• {vt_text}
• {ml_text}

**TASK:** Provide a comprehensive, detailed threat analysis. Be thorough and specific.

**ANALYSIS REQUIREMENTS:**

1. **Domain Analysis:**
   - Examine domain legitimacy, age, reputation
   - Check for typosquatting, homograph attacks, suspicious TLDs
   - Identify brand impersonation attempts

2. **URL Structure Assessment:**
   - Analyze suspicious patterns (excessive subdomains, long paths, encoded characters)
   - Check for redirection tactics, URL shorteners
   - Evaluate use of IP addresses vs domain names

3. **Security Indicators:**
   - SSL/HTTPS usage and validity concerns
   - Presence of phishing keywords (login, verify, account, urgent, suspended)
   - Suspicious query parameters or fragments

4. **Behavioral Patterns:**
   - Compare against known phishing/malware campaigns
   - Cross-reference with VirusTotal and ML model findings
   - Identify social engineering tactics

5. **Risk Assessment:**
   - Provide overall verdict with high confidence
   - List specific red flags or green flags
   - Explain reasoning clearly

**OUTPUT FORMAT (strict JSON):**
{{
  "verdict": "Safe" or "Suspicious" or "Malicious",
  "confidence_score": <integer 0-100>,
  "risk_level": "Low" or "Medium" or "High" or "Critical",
  "explanation": "<3-5 sentences explaining the verdict with specific evidence from the URL>",
  "detailed_findings": {{
    "domain_analysis": "<2-3 sentences about domain legitimacy>",
    "url_structure": "<2-3 sentences about URL patterns and structure>",
    "security_indicators": "<2-3 sentences about security concerns or positives>",
    "threat_correlation": "<2-3 sentences comparing with VirusTotal/ML findings>"
  }},
  "red_flags": ["<specific issue 1>", "<specific issue 2>", "..."],
  "green_flags": ["<positive indicator 1>", "<positive indicator 2>", "..."],
  "recommendations": ["<action 1>", "<action 2>", "<action 3>"]
}}

Return ONLY valid JSON. Be specific and detailed."""
        
        response = model.generate_content(prompt, generation_config={'temperature': 0.3, 'max_output_tokens': 2048})
        text = response.text.strip() if hasattr(response, 'text') else str(response)
        text = re.sub(r"^```json|```\n|```", "", text).strip()
        m = re.search(r"\{.*\}", text, flags=re.DOTALL)
        json_text = m.group(0) if m else text
        result = json.loads(json_text)
        return {
            "available": True, 
            "verdict": result.get("verdict", "Unknown"), 
            "confidence_score": result.get("confidence_score", 50), 
            "risk_level": result.get("risk_level", "Medium"), 
            "explanation": result.get("explanation", ""), 
            "detailed_findings": result.get("detailed_findings", {}),
            "red_flags": result.get("red_flags", []),
            "green_flags": result.get("green_flags", []),
            "recommendations": result.get("recommendations", [])
        }
    except Exception as e:
        return {"available": False, "message": f"AI Error: {str(e)}"}

# -------------------------
# Combined Analysis
# -------------------------
def get_combined_verdict(ml_result, vt_result, ai_result):
    scores = []
    weights = []
    
    if ml_result['verdict'] == 'Phishing':
        scores.append(-50)
        weights.append(1.0)
    elif ml_result['verdict'] == 'Legitimate':
        scores.append(50)
        weights.append(1.0)
    
    if vt_result.get('available'):
        if vt_result['verdict'] == 'Malicious':
            scores.append(-100)
            weights.append(2.5)
        elif vt_result['verdict'] == 'Suspicious':
            scores.append(-50)
            weights.append(2.0)
        elif vt_result['verdict'] == 'Safe':
            scores.append(40)
            weights.append(1.5)
    
    if ai_result.get('available'):
        ai_verdict = ai_result['verdict']
        ai_confidence = ai_result.get('confidence_score', 50)
        if ai_verdict == 'Malicious':
            scores.append(-100)
            weights.append(3.0)
        elif ai_verdict == 'Suspicious':
            scores.append(-70)
            weights.append(2.5)
        elif ai_verdict == 'Safe':
            scores.append(50)
            weights.append(2.0)
    
    if not scores:
        avg_score = 0
    else:
        weighted_sum = sum(s * w for s, w in zip(scores, weights))
        total_weight = sum(weights)
        avg_score = weighted_sum / total_weight
    
    if ai_result.get('available') and ai_result['verdict'] in ['Malicious', 'Suspicious']:
        if avg_score > -20:
            avg_score = -20
    
    if avg_score < -50:
        return "Malicious", "Critical"
    elif avg_score < -15:
        return "Suspicious", "High"
    elif avg_score < 10:
        return "Suspicious", "Medium"
    else:
        return "Safe", "Low"

# -------------------------
# Flask Routes
# -------------------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    try:
        ml_result = get_ml_prediction(url)
        features = extract_advanced_features(url)
        vt_result = check_virustotal(url)
        ai_result = analyze_with_gemini(url, features, vt_result, ml_result)
        final_verdict, risk_level = get_combined_verdict(ml_result, vt_result, ai_result)
        confidences = []
        if ml_result['confidence'] > 0:
            confidences.append(ml_result['confidence'])
        if ai_result.get('available') and ai_result.get('confidence_score'):
            confidences.append(ai_result['confidence_score'])
        overall_confidence = int(sum(confidences) / len(confidences)) if confidences else 50
        return jsonify({'success': True,'url': url,'final_verdict': final_verdict,'risk_level': risk_level,'confidence': overall_confidence,'timestamp': datetime.now().isoformat(),'details': {'ml_model': ml_result,'virustotal': vt_result,'ai_analysis': ai_result,'features': features}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    gemini_ok = False
    if GEMINI_API_KEY:
        try:
            _model = genai.GenerativeModel('models/gemini-2.0-flash')
            _model.count_tokens("ping")
            gemini_ok = True
        except Exception:
            gemini_ok = False
    return jsonify({'status': 'healthy','ml_model': ml_model is not None,'gemini_api': gemini_ok,'virustotal_api': VIRUSTOTAL_API_KEY is not None})

if __name__ == '__main__':
    webbrowser.open('http://127.0.0.1:5000/')
    app.run(debug=True, port=5000)

