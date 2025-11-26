from flask import Flask, request, jsonify, render_template_string
import joblib
import numpy as np
from urllib.parse import urlparse
import webbrowser
import os
import requests
import re
import json
import tldextract
import google.generativeai as genai
from datetime import datetime

# -------------------------
# CONFIG & SECRETS
# -------------------------
app = Flask(__name__)

# Try to load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

MODEL_PATH = 'model.pkl'
try:
    ml_model = joblib.load(MODEL_PATH)
    print("✅ ML Model loaded")
except Exception as e:
    print(f"❌ ML Model load error: {e}")
    ml_model = None

# -------------------------
# EMBEDDED HTML TEMPLATE
# -------------------------
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebGuard - URL Security Analyzer</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --bg-dark: #0a0a0a;
            --bg-card: #1a1a1a;
            --border: #2a2a2a;
            --text: #ffffff;
            --text-dim: #888888;
            --primary: #f59e0b;
            --secondary: #ea580c;
            --success: #22c55e;
            --warning: #eab308;
            --danger: #ef4444;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
            color: var(--text);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container { max-width: 1200px; margin: 0 auto; }
        
        .header { text-align: center; margin-bottom: 40px; padding: 20px; }
        
        .logo {
            font-size: 2.5rem;
            font-weight: bold;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }
        
        .tagline { color: var(--text-dim); font-size: 1.1rem; }
        
        .status-badges {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin-top: 15px;
            flex-wrap: wrap;
        }
        
        .badge {
            padding: 6px 16px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 20px;
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .badge.active { border-color: var(--success); }
        
        .badge-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--danger);
        }
        
        .badge.active .badge-dot { background: var(--success); }
        
        .input-section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
        }
        
        .input-group { display: flex; gap: 15px; }
        
        #urlInput {
            flex: 1;
            padding: 15px 20px;
            background: var(--bg-dark);
            border: 2px solid var(--border);
            border-radius: 10px;
            color: var(--text);
            font-size: 1rem;
        }
        
        #urlInput:focus {
            outline: none;
            border-color: var(--primary);
        }
        
        .btn-analyze {
            padding: 15px 40px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border: none;
            border-radius: 10px;
            color: white;
            font-weight: 600;
            cursor: pointer;
            font-size: 1rem;
            transition: transform 0.2s;
        }
        
        .btn-analyze:hover { transform: translateY(-2px); }
        .btn-analyze:disabled { opacity: 0.5; cursor: not-allowed; }
        
        .loading {
            text-align: center;
            padding: 60px 20px;
            display: none;
        }
        
        .loading.show { display: block; }
        
        .spinner {
            width: 60px;
            height: 60px;
            border: 4px solid var(--border);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin { to { transform: rotate(360deg); } }
        
        .results {
            display: none;
        }
        
        .results.show { display: block; }
        
        .final-verdict {
            background: var(--bg-card);
            border: 3px solid;
            border-radius: 16px;
            padding: 50px;
            text-align: center;
            margin-bottom: 30px;
            position: relative;
            overflow: hidden;
        }
        
        .final-verdict::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 6px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
        }
        
        .final-verdict.legitimate {
            border-color: var(--success);
            background: linear-gradient(135deg, rgba(34, 197, 94, 0.05), rgba(34, 197, 94, 0.02));
        }
        
        .final-verdict.phishing {
            border-color: var(--danger);
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.05), rgba(239, 68, 68, 0.02));
        }
        
        .verdict-icon {
            font-size: 100px;
            margin-bottom: 20px;
            animation: scaleIn 0.5s ease;
        }
        
        @keyframes scaleIn {
            from { transform: scale(0); }
            to { transform: scale(1); }
        }
        
        .verdict-title {
            font-size: 3rem;
            font-weight: bold;
            margin-bottom: 10px;
            letter-spacing: 2px;
        }
        
        .verdict-title.legitimate { color: var(--success); }
        .verdict-title.phishing { color: var(--danger); }
        
        .verdict-subtitle {
            font-size: 1.1rem;
            color: var(--text-dim);
            margin-bottom: 25px;
            word-break: break-all;
        }
        
        .risk-level {
            display: inline-block;
            padding: 12px 40px;
            border-radius: 30px;
            font-weight: 700;
            font-size: 1.2rem;
            margin: 20px 0;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .risk-low { background: var(--success); color: white; }
        .risk-medium { background: var(--warning); color: #000; }
        .risk-high { background: var(--danger); color: white; }
        .risk-critical { background: #dc2626; color: white; animation: pulse 2s infinite; }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .confidence-bar-container {
            max-width: 500px;
            margin: 20px auto 0;
        }
        
        .confidence-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            color: var(--text-dim);
            font-size: 1rem;
        }
        
        .confidence-bar {
            height: 35px;
            background: var(--bg-dark);
            border-radius: 18px;
            overflow: hidden;
            border: 1px solid var(--border);
        }
        
        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            transition: width 0.8s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.1rem;
        }
        
        .report-section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .report-header {
            padding: 20px 25px;
            background: rgba(245, 158, 11, 0.05);
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .report-header:hover { background: rgba(245, 158, 11, 0.1); }
        
        .report-header-left {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .report-icon { font-size: 2rem; }
        
        .report-title {
            font-size: 1.3rem;
            font-weight: 600;
        }
        
        .report-subtitle {
            font-size: 0.875rem;
            color: var(--text-dim);
            margin-top: 4px;
        }
        
        .report-badge {
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
        }
        
        .report-badge.safe { background: var(--success); color: white; }
        .report-badge.malicious { background: var(--danger); color: white; }
        .report-badge.phishing { background: var(--danger); color: white; }
        .report-badge.legitimate { background: var(--success); color: white; }
        .report-badge.unavailable { background: var(--bg-dark); color: var(--text-dim); }
        
        .report-toggle {
            font-size: 1.5rem;
            transition: transform 0.3s;
        }
        
        .report-toggle.open { transform: rotate(180deg); }
        
        .report-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.4s ease;
        }
        
        .report-content.open { max-height: 3000px; }
        
        .report-body { padding: 25px; }
        
        .report-item { margin-bottom: 25px; }
        
        .report-item-title {
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 10px;
            font-size: 1.1rem;
        }
        
        .report-item-text {
            color: var(--text);
            line-height: 1.6;
        }
        
        .flag-list {
            list-style: none;
            padding: 0;
        }
        
        .flag-item {
            padding: 12px 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            display: flex;
            align-items: flex-start;
            gap: 10px;
            line-height: 1.5;
        }
        
        .flag-item.red {
            background: rgba(239, 68, 68, 0.1);
            border-left: 4px solid var(--danger);
        }
        
        .flag-item.green {
            background: rgba(34, 197, 94, 0.1);
            border-left: 4px solid var(--success);
        }
        
        .flag-item.neutral {
            background: rgba(245, 158, 11, 0.1);
            border-left: 4px solid var(--primary);
        }
        
        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .detail-item {
            background: var(--bg-dark);
            padding: 15px;
            border-radius: 8px;
        }
        
        .detail-label {
            color: var(--text-dim);
            font-size: 0.875rem;
            margin-bottom: 6px;
        }
        
        .detail-value {
            font-weight: 600;
            font-size: 1.1rem;
        }
        
        .detail-value.true { color: var(--success); }
        .detail-value.false { color: var(--danger); }
        
        .vt-stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
        }
        
        .vt-stat {
            background: var(--bg-dark);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .vt-stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 8px;
        }
        
        .vt-stat-value.malicious { color: var(--danger); }
        .vt-stat-value.suspicious { color: var(--warning); }
        .vt-stat-value.harmless { color: var(--success); }
        
        .vt-stat-label {
            color: var(--text-dim);
            font-size: 0.875rem;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: var(--text-dim);
            margin-top: 40px;
            border-top: 1px solid var(--border);
        }
        
        @media (max-width: 768px) {
            .input-group { flex-direction: column; }
            .vt-stats { grid-template-columns: repeat(2, 1fr); }
            .details-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ WebGuard</div>
            <div class="tagline">Advanced URL Security Analyzer</div>
            <p style="color: var(--text-dim); margin-top: 10px;">Multi-layered protection using ML, AI, and threat intelligence</p>
            <div class="status-badges" id="statusBadges">
                <div class="badge"><span class="badge-dot"></span> ML Model</div>
                <div class="badge"><span class="badge-dot"></span> Gemini AI</div>
                <div class="badge"><span class="badge-dot"></span> VirusTotal</div>
            </div>
        </div>
        
        <div class="input-section">
            <form id="urlForm">
                <div class="input-group">
                    <input type="url" id="urlInput" placeholder="Enter URL to analyze (e.g., https://example.com)..." required>
                    <button type="submit" class="btn-analyze" id="analyzeBtn">
                        <span id="btnText">🔍 Analyze URL</span>
                    </button>
                </div>
            </form>
        </div>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <h3>Analyzing URL...</h3>
            <p style="color: var(--text-dim); margin-top: 10px;">Running multi-layered security scan</p>
        </div>
        
        <div class="results" id="results">
            <div class="final-verdict" id="finalVerdict">
                <div class="verdict-icon" id="verdictIcon">✅</div>
                <div class="verdict-title" id="verdictTitle">LEGITIMATE</div>
                <div class="verdict-subtitle" id="verdictUrl"></div>
                <div class="risk-level" id="riskLevel">Risk Level: Low</div>
                <div class="confidence-bar-container">
                    <div class="confidence-label">
                        <span>Overall Confidence Score</span>
                        <span id="confidencePercent">0%</span>
                    </div>
                    <div class="confidence-bar">
                        <div class="confidence-fill" id="confidenceFill" style="width: 0%">
                            <span id="confidenceText">0%</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="report-section" id="aiReport">
                <div class="report-header" onclick="toggleReport('ai')">
                    <div class="report-header-left">
                        <div class="report-icon">🤖</div>
                        <div>
                            <div class="report-title">Gemini AI Analysis</div>
                            <div class="report-subtitle">Comprehensive threat intelligence</div>
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <div class="report-badge" id="aiBadge">Safe</div>
                        <div class="report-toggle" id="aiToggle">▼</div>
                    </div>
                </div>
                <div class="report-content" id="aiContent">
                    <div class="report-body" id="aiBody">
                        <div class="report-item">
                            <div class="report-item-title">🎯 Overall Assessment</div>
                            <div class="report-item-text" id="aiExplanation">Loading...</div>
                        </div>
                        <div class="report-item" id="aiDetailedSection" style="display: none;">
                            <div class="report-item-title">🔍 Detailed Findings</div>
                            <div style="margin-top: 15px;">
                                <div style="margin-bottom: 15px;">
                                    <strong style="color: var(--primary);">Domain Analysis:</strong>
                                    <div class="report-item-text" id="aiDomain" style="margin-top: 5px;">-</div>
                                </div>
                                <div style="margin-bottom: 15px;">
                                    <strong style="color: var(--primary);">URL Structure:</strong>
                                    <div class="report-item-text" id="aiUrlStructure" style="margin-top: 5px;">-</div>
                                </div>
                                <div style="margin-bottom: 15px;">
                                    <strong style="color: var(--primary);">Security Indicators:</strong>
                                    <div class="report-item-text" id="aiSecurity" style="margin-top: 5px;">-</div>
                                </div>
                                <div>
                                    <strong style="color: var(--primary);">Threat Correlation:</strong>
                                    <div class="report-item-text" id="aiThreat" style="margin-top: 5px;">-</div>
                                </div>
                            </div>
                        </div>
                        <div class="report-item" id="aiRedSection" style="display: none;">
                            <div class="report-item-title">🚩 Red Flags</div>
                            <ul class="flag-list" id="aiRedList"></ul>
                        </div>
                        <div class="report-item" id="aiGreenSection" style="display: none;">
                            <div class="report-item-title">✅ Green Flags</div>
                            <ul class="flag-list" id="aiGreenList"></ul>
                        </div>
                        <div class="report-item" id="aiRecSection">
                            <div class="report-item-title">💡 Recommendations</div>
                            <ul class="flag-list" id="aiRecList"></ul>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="report-section" id="vtReport">
                <div class="report-header" onclick="toggleReport('vt')">
                    <div class="report-header-left">
                        <div class="report-icon">🛡️</div>
                        <div>
                            <div class="report-title">VirusTotal Analysis</div>
                            <div class="report-subtitle">70+ security vendor checks</div>
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <div class="report-badge" id="vtBadge">Safe</div>
                        <div class="report-toggle" id="vtToggle">▼</div>
                    </div>
                </div>
                <div class="report-content" id="vtContent">
                    <div class="report-body">
                        <div class="vt-stats" id="vtStats"></div>
                    </div>
                </div>
            </div>
            
            <div class="report-section" id="mlReport">
                <div class="report-header" onclick="toggleReport('ml')">
                    <div class="report-header-left">
                        <div class="report-icon">🤖</div>
                        <div>
                            <div class="report-title">ML Model Analysis</div>
                            <div class="report-subtitle">Pattern-based detection</div>
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <div class="report-badge" id="mlBadge">Legitimate</div>
                        <div class="report-toggle" id="mlToggle">▼</div>
                    </div>
                </div>
                <div class="report-content" id="mlContent">
                    <div class="report-body">
                        <div class="report-item">
                            <div class="report-item-title">📊 Classification Result</div>
                            <div class="report-item-text" id="mlDetail">Loading...</div>
                        </div>
                        <div class="report-item">
                            <div class="report-item-title">🎯 Confidence Score</div>
                            <div class="report-item-text" id="mlConfText">Loading...</div>
                        </div>
                        <div class="report-item">
                            <div class="report-item-title">🔍 Technical Features</div>
                            <div class="details-grid" id="detailsGrid"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Built with ML + Gemini AI + VirusTotal + Flask 💙</p>
            <p style="margin-top: 8px; font-size: 0.875rem;">Stay safe online!</p>
        </div>
    </div>
    
    <script>
        fetch('/health').then(res => res.json()).then(data => {
            const badges = document.querySelectorAll('.badge');
            if (data.ml_model) badges[0].classList.add('active');
            if (data.gemini_api) badges[1].classList.add('active');
            if (data.virustotal_api) badges[2].classList.add('active');
        }).catch(err => console.error('Health check failed:', err));
        
        function toggleReport(section) {
            const content = document.getElementById(section + 'Content');
            const toggle = document.getElementById(section + 'Toggle');
            content.classList.toggle('open');
            toggle.classList.toggle('open');
        }
        
        document.getElementById('urlForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const url = document.getElementById('urlInput').value.trim();
            if (!url) return;
            
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');
            const analyzeBtn = document.getElementById('analyzeBtn');
            const btnText = document.getElementById('btnText');
            
            loading.classList.add('show');
            results.classList.remove('show');
            analyzeBtn.disabled = true;
            btnText.textContent = '⏳ Analyzing...';
            
            try {
                const response = await fetch('/predict', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();
                if (data.error) { alert('Error: ' + data.error); return; }
                displayResults(data);
            } catch (error) {
                console.error('Error:', error);
                alert('Failed to analyze URL. Please check if the backend is running.');
            } finally {
                loading.classList.remove('show');
                analyzeBtn.disabled = false;
                btnText.textContent = '🔍 Analyze URL';
            }
        });
        
        function displayResults(data) {
            const results = document.getElementById('results');
            results.classList.add('show');
            
            const verdict = data.final_verdict.toLowerCase() === 'safe' ? 'legitimate' : (data.final_verdict.toLowerCase() === 'malicious' ? 'phishing' : data.final_verdict.toLowerCase());
            const verdictText = verdict === 'legitimate' ? 'LEGITIMATE' : (verdict === 'phishing' ? 'PHISHING' : data.final_verdict.toUpperCase());
            
            document.getElementById('finalVerdict').className = 'final-verdict ' + verdict;
            document.getElementById('verdictTitle').className = 'verdict-title ' + verdict;
            const icons = { 'legitimate': '✅', 'phishing': '🚨', 'suspicious': '⚠️' };
            document.getElementById('verdictIcon').textContent = icons[verdict] || '❓';
            document.getElementById('verdictTitle').textContent = verdictText;
            document.getElementById('verdictUrl').textContent = data.url;
            document.getElementById('riskLevel').textContent = `Risk Level: ${data.risk_level}`;
            document.getElementById('riskLevel').className = 'risk-level risk-' + data.risk_level.toLowerCase();
            
            const confidence = data.confidence;
            document.getElementById('confidencePercent').textContent = confidence + '%';
            document.getElementById('confidenceFill').style.width = confidence + '%';
            document.getElementById('confidenceText').textContent = confidence + '%';
            
            const ml = data.details.ml_model;
            const mlVerdict = ml.verdict.toLowerCase();
            document.getElementById('mlBadge').textContent = ml.verdict;
            document.getElementById('mlBadge').className = 'report-badge ' + mlVerdict;
            document.getElementById('mlDetail').textContent = ml.reason || 'ML model classified this URL based on structural patterns.';
            document.getElementById('mlConfText').textContent = `Confidence: ${ml.confidence}%`;
            
            if (data.details.ai_analysis && data.details.ai_analysis.available) {
                const ai = data.details.ai_analysis;
                const aiVerdict = ai.verdict.toLowerCase();
                document.getElementById('aiBadge').textContent = ai.verdict;
                document.getElementById('aiBadge').className = 'report-badge ' + (aiVerdict === 'safe' ? 'safe' : aiVerdict);
                document.getElementById('aiExplanation').textContent = ai.explanation || 'No explanation provided.';
                
                if (ai.detailed_findings) {
                    document.getElementById('aiDetailedSection').style.display = 'block';
                    document.getElementById('aiDomain').textContent = ai.detailed_findings.domain_analysis || 'N/A';
                    document.getElementById('aiUrlStructure').textContent = ai.detailed_findings.url_structure || 'N/A';
                    document.getElementById('aiSecurity').textContent = ai.detailed_findings.security_indicators || 'N/A';
                    document.getElementById('aiThreat').textContent = ai.detailed_findings.threat_correlation || 'N/A';
                } else {
                    document.getElementById('aiDetailedSection').style.display = 'none';
                }
                
                if (ai.red_flags && ai.red_flags.length > 0) {
                    document.getElementById('aiRedSection').style.display = 'block';
                    const redList = document.getElementById('aiRedList');
                    redList.innerHTML = '';
                    ai.red_flags.forEach(flag => {
                        const li = document.createElement('li');
                        li.className = 'flag-item red';
                        li.innerHTML = '<span>🚩</span><span>' + flag + '</span>';
                        redList.appendChild(li);
                    });
                } else {
                    document.getElementById('aiRedSection').style.display = 'none';
                }
                
                if (ai.green_flags && ai.green_flags.length > 0) {
                    document.getElementById('aiGreenSection').style.display = 'block';
                    const greenList = document.getElementById('aiGreenList');
                    greenList.innerHTML = '';
                    ai.green_flags.forEach(flag => {
                        const li = document.createElement('li');
                        li.className = 'flag-item green';
                        li.innerHTML = '<span>✅</span><span>' + flag + '</span>';
                        greenList.appendChild(li);
                    });
                } else {
                    document.getElementById('aiGreenSection').style.display = 'none';
                }
                
                if (ai.recommendations && ai.recommendations.length > 0) {
                    const recList = document.getElementById('aiRecList');
                    recList.innerHTML = '';
                    ai.recommendations.forEach(rec => {
                        const li = document.createElement('li');
                        li.className = 'flag-item neutral';
                        li.innerHTML = '<span>💡</span><span>' + rec + '</span>';
                        recList.appendChild(li);
                    });
                } else {
                    document.getElementById('aiRecSection').style.display = 'none';
                }
            } else {
                const aiMessage = (data.details.ai_analysis && data.details.ai_analysis.message) ? data.details.ai_analysis.message : 'AI analysis not available';
                document.getElementById('aiBadge').textContent = 'Unavailable';
                document.getElementById('aiBadge').className = 'report-badge unavailable';
                document.getElementById('aiExplanation').textContent = aiMessage;
                document.getElementById('aiDetailedSection').style.display = 'none';
                document.getElementById('aiRedSection').style.display = 'none';
                document.getElementById('aiGreenSection').style.display = 'none';
                document.getElementById('aiRecSection').style.display = 'none';
            }
            
            if (data.details.virustotal && data.details.virustotal.available) {
                const vt = data.details.virustotal;
                const vtVerdict = vt.verdict.toLowerCase();
                document.getElementById('vtBadge').textContent = vt.verdict;
                document.getElementById('vtBadge').className = 'report-badge ' + vtVerdict;
                document.getElementById('vtStats').innerHTML = `
                    <div class="vt-stat">
                        <div class="vt-stat-value malicious">${vt.malicious}</div>
                        <div class="vt-stat-label">Malicious</div>
                    </div>
                    <div class="vt-stat">
                        <div class="vt-stat-value suspicious">${vt.suspicious}</div>
                        <div class="vt-stat-label">Suspicious</div>
                    </div>
                    <div class="vt-stat">
                        <div class="vt-stat-value harmless">${vt.harmless}</div>
                        <div class="vt-stat-label">Harmless</div>
                    </div>
                    <div class="vt-stat">
                        <div class="vt-stat-value">${vt.undetected}</div>
                        <div class="vt-stat-label">Undetected</div>
                    </div>
                `;
            } else {
                document.getElementById('vtBadge').textContent = 'Unavailable';
                document.getElementById('vtBadge').className = 'report-badge unavailable';
                document.getElementById('vtStats').innerHTML = '<p style="color: var(--text-dim);">VirusTotal not configured or unavailable</p>';
            }
            
            const features = data.details.features;
            const detailsGrid = document.getElementById('detailsGrid');
            detailsGrid.innerHTML = '';
            for (const [key, value] of Object.entries(features)) {
                const item = document.createElement('div');
                item.className = 'detail-item';
                const label = document.createElement('div');
                label.className = 'detail-label';
                label.textContent = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                const valueDiv = document.createElement('div');
                valueDiv.className = 'detail-value';
                if (typeof value === 'boolean') {
                    valueDiv.classList.add(value ? 'true' : 'false');
                    valueDiv.textContent = value ? '✓ Yes' : '✗ No';
                } else {
                    valueDiv.textContent = value;
                }
                item.appendChild(label);
                item.appendChild(valueDiv);
                detailsGrid.appendChild(item);
            }
            results.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    </script>
</body>
</html>'''

# -------------------------
# ML LOGIC (Merged from predictor.py)
# -------------------------
def extract_ml_features(url):
    """Extract simple numerical features for the ML model."""
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
# ENHANCED FEATURES & API LOGIC
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
# FLASK ROUTES
# -------------------------
@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

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
