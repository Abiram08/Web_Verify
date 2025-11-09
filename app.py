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

app = Flask(__name__)

# -------------------------
# Configuration
# -------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except:
    pass

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Configure Gemini
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Load the ML model
MODEL_PATH = 'model.pkl'
try:
    ml_model = joblib.load(MODEL_PATH)
    print("✅ ML Model loaded successfully!")
except Exception as e:
    print(f"⚠️ Warning: Could not load ML model: {e}")
    ml_model = None

# -------------------------
# ML Feature Extraction
# -------------------------
def extract_ml_features(url):
    """Extract features for ML model prediction."""
    parsed_url = urlparse(url)
    domain_name = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query
    features = [
        len(url),  # Length of the URL
        domain_name.count('.'),  # Count of '.' in the domain
        len(domain_name),  # Length of the domain name
        url.count('/'),  # Count of '/' in the URL
        len(path),  # Length of the URL path
        len(query)  # Length of the query string
    ]
    return np.array(features).reshape(1, -1)

def get_ml_prediction(url):
    """Get ML model prediction."""
    if not ml_model:
        return {"verdict": "Unknown", "confidence": 0, "reason": "ML model not available"}
    
    try:
        features = extract_ml_features(url)
        prediction = ml_model.predict(features)
        proba = ml_model.predict_proba(features) if hasattr(ml_model, 'predict_proba') else None
        
        verdict = 'Legitimate' if prediction[0] == 1 else 'Phishing'
        confidence = int(proba[0][prediction[0]] * 100) if proba is not None else 85
        
        return {
            "verdict": verdict,
            "confidence": confidence,
            "reason": f"ML model analyzed URL structure and patterns"
        }
    except Exception as e:
        return {"verdict": "Unknown", "confidence": 0, "reason": f"ML Error: {str(e)}"}

# -------------------------
# Enhanced Feature Extraction for AI
# -------------------------
def extract_advanced_features(url):
    """Extract advanced features for AI analysis."""
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    
    features = {
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
        "has_suspicious_keywords": any(kw in url.lower() for kw in 
            ['login', 'verify', 'account', 'update', 'secure', 'banking', 'paypal', 'ebay'])
    }
    return features

# -------------------------
# VirusTotal Integration
# -------------------------
def check_virustotal(url):
    """Check URL against VirusTotal database."""
    if not VIRUSTOTAL_API_KEY:
        return {"available": False, "message": "VirusTotal API key not configured"}
    
    try:
        url_id = quote(url, safe='')
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        # Submit URL for scanning
        scan_url = "https://www.virustotal.com/api/v3/urls"
        scan_response = requests.post(scan_url, headers=headers, data={"url": url}, timeout=10)
        
        if scan_response.status_code != 200:
            return {"available": False, "message": "VirusTotal scan failed"}
        
        # Get analysis results
        analysis_id = scan_response.json()['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers=headers, timeout=10)
        
        if analysis_response.status_code == 200:
            data = analysis_response.json()['data']['attributes']
            stats = data.get('stats', {})
            
            return {
                "available": True,
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "undetected": stats.get('undetected', 0),
                "verdict": "Malicious" if stats.get('malicious', 0) > 0 else 
                          "Suspicious" if stats.get('suspicious', 0) > 0 else "Safe"
            }
        
        return {"available": False, "message": "Could not retrieve analysis"}
    except Exception as e:
        return {"available": False, "message": f"Error: {str(e)}"}

# -------------------------
# Gemini AI Analysis
# -------------------------
def analyze_with_gemini(url, features, vt_data, ml_data):
    """Analyze URL using Gemini AI."""
    if not GEMINI_API_KEY:
        return {"available": False, "message": "Gemini API key not configured"}
    
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        feature_text = "\n".join([f"{k}: {v}" for k, v in features.items()])
        vt_text = f"VirusTotal: {vt_data.get('verdict', 'N/A')}" if vt_data.get('available') else "VirusTotal: Not available"
        ml_text = f"ML Model: {ml_data.get('verdict', 'Unknown')} ({ml_data.get('confidence', 0)}% confidence)"
        
        prompt = f"""You are a cybersecurity expert. Analyze this URL and provide a comprehensive assessment.

URL: {url}

Features:
{feature_text}

{vt_text}
{ml_text}

Provide a JSON response with:
- verdict: "Safe" / "Suspicious" / "Malicious"
- confidence_score: integer 0-100
- risk_level: "Low" / "Medium" / "High" / "Critical"
- explanation: detailed 2-3 sentence analysis
- recommendations: list of 2-3 specific action items

Return ONLY valid JSON."""

        response = model.generate_content(
            prompt,
            generation_config={'temperature': 0.2, 'max_output_tokens': 512}
        )
        
        text = response.text.strip()
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
            "recommendations": result.get("recommendations", [])
        }
        
    except Exception as e:
        return {"available": False, "message": f"AI Error: {str(e)}"}

# -------------------------
# Combined Analysis
# -------------------------
def get_combined_verdict(ml_result, vt_result, ai_result):
    """Combine all predictions into final verdict."""
    scores = []
    
    # ML Model score
    if ml_result['verdict'] == 'Phishing':
        scores.append(-50)
    elif ml_result['verdict'] == 'Legitimate':
        scores.append(50)
    
    # VirusTotal score
    if vt_result.get('available'):
        if vt_result['verdict'] == 'Malicious':
            scores.append(-100)
        elif vt_result['verdict'] == 'Suspicious':
            scores.append(-30)
        elif vt_result['verdict'] == 'Safe':
            scores.append(70)
    
    # AI score
    if ai_result.get('available'):
        if ai_result['verdict'] == 'Malicious':
            scores.append(-80)
        elif ai_result['verdict'] == 'Suspicious':
            scores.append(-40)
        elif ai_result['verdict'] == 'Safe':
            scores.append(60)
    
    avg_score = sum(scores) / len(scores) if scores else 0
    
    if avg_score < -40:
        return "Malicious", "Critical"
    elif avg_score < -10:
        return "Suspicious", "High"
    elif avg_score < 20:
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
        # 1. ML Model Analysis
        ml_result = get_ml_prediction(url)
        
        # 2. Extract Features
        features = extract_advanced_features(url)
        
        # 3. VirusTotal Check
        vt_result = check_virustotal(url)
        
        # 4. Gemini AI Analysis
        ai_result = analyze_with_gemini(url, features, vt_result, ml_result)
        
        # 5. Combined Verdict
        final_verdict, risk_level = get_combined_verdict(ml_result, vt_result, ai_result)
        
        # Calculate overall confidence
        confidences = []
        if ml_result['confidence'] > 0:
            confidences.append(ml_result['confidence'])
        if ai_result.get('available') and ai_result.get('confidence_score'):
            confidences.append(ai_result['confidence_score'])
        
        overall_confidence = int(sum(confidences) / len(confidences)) if confidences else 50
        
        return jsonify({
            'success': True,
            'url': url,
            'final_verdict': final_verdict,
            'risk_level': risk_level,
            'confidence': overall_confidence,
            'timestamp': datetime.now().isoformat(),
            'details': {
                'ml_model': ml_result,
                'virustotal': vt_result,
                'ai_analysis': ai_result,
                'features': features
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'ml_model': ml_model is not None,
        'gemini_api': GEMINI_API_KEY is not None,
        'virustotal_api': VIRUSTOTAL_API_KEY is not None
    })

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  WebGuard - Advanced URL Security Analyzer")
    print("="*60)
    print(f"✅ ML Model: {'Loaded' if ml_model else 'Not Available'}")
    print(f"✅ Gemini AI: {'Configured' if GEMINI_API_KEY else 'Not Configured'}")
    print(f"✅ VirusTotal: {'Configured' if VIRUSTOTAL_API_KEY else 'Not Configured'}")
    print("="*60)
    print("🚀 Starting server at http://127.0.0.1:5000/")
    print("="*60 + "\n")
    
    # Open browser
    webbrowser.open('http://127.0.0.1:5000/')
    app.run(debug=True, port=5000)

