#!/usr/bin/env python3
"""Script to create the index.html file"""

html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebGuard - URL Security Analyzer</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

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

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
            padding: 20px;
        }

        .logo {
            font-size: 2.5rem;
            font-weight: bold;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }

        .tagline {
            color: var(--text-dim);
            font-size: 1.1rem;
        }

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

        .badge.active {
            background: var(--success);
            border-color: var(--success);
            color: white;
        }

        .badge-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: currentColor;
        }

        .input-section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
        }

        .input-group {
            display: flex;
            gap: 12px;
        }

        #urlInput {
            flex: 1;
            padding: 14px 20px;
            background: var(--bg-dark);
            border: 2px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 16px;
            transition: border-color 0.3s;
        }

        #urlInput:focus {
            outline: none;
            border-color: var(--primary);
        }

        .btn-analyze {
            padding: 14px 32px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border: none;
            border-radius: 8px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, opacity 0.3s;
        }

        .btn-analyze:hover:not(:disabled) {
            transform: translateY(-2px);
            opacity: 0.9;
        }

        .btn-analyze:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .loading {
            display: none;
            text-align: center;
            padding: 40px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 30px;
        }

        .loading.show {
            display: block;
        }

        .spinner {
            width: 50px;
            height: 50px;
            border: 4px solid var(--border);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .results {
            display: none;
        }

        .results.show {
            display: block;
        }

        .final-verdict {
            background: var(--bg-card);
            border: 3px solid;
            border-radius: 16px;
            padding: 40px;
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
            height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
        }

        .final-verdict.safe {
            border-color: var(--success);
        }

        .final-verdict.suspicious {
            border-color: var(--warning);
        }

        .final-verdict.malicious {
            border-color: var(--danger);
        }

        .verdict-icon {
            font-size: 80px;
            margin-bottom: 20px;
        }

        .verdict-title {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 15px;
        }

        .verdict-subtitle {
            font-size: 1.2rem;
            color: var(--text-dim);
            margin-bottom: 25px;
        }

        .risk-level {
            display: inline-block;
            padding: 10px 30px;
            border-radius: 25px;
            font-weight: 600;
            font-size: 1.1rem;
            margin-bottom: 20px;
        }

        .risk-low { background: var(--success); color: white; }
        .risk-medium { background: var(--warning); color: white; }
        .risk-high { background: var(--danger); color: white; }
        .risk-critical { background: #dc2626; color: white; }

        .confidence-bar-container {
            max-width: 400px;
            margin: 0 auto;
        }

        .confidence-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            color: var(--text-dim);
        }

        .confidence-bar {
            height: 30px;
            background: var(--bg-dark);
            border-radius: 15px;
            overflow: hidden;
        }

        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
        }

        .analysis-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .analysis-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 25px;
            transition: transform 0.2s, border-color 0.2s;
        }

        .analysis-card:hover {
            transform: translateY(-4px);
            border-color: var(--primary);
        }

        .analysis-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border);
        }

        .analysis-icon {
            font-size: 32px;
        }

        .analysis-title {
            font-size: 1.3rem;
            font-weight: 600;
        }

        .analysis-result {
            font-size: 1.8rem;
            font-weight: bold;
            margin-bottom: 10px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .analysis-detail {
            color: var(--text-dim);
            margin-bottom: 8px;
        }

        .analysis-badge {
            display: inline-block;
            padding: 4px 12px;
            background: var(--bg-dark);
            border-radius: 12px;
            font-size: 0.875rem;
            margin-top: 10px;
        }

        .section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
        }

        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            color: var(--primary);
        }

        .section-icon {
            font-size: 24px;
        }

        .ai-explanation {
            background: var(--bg-dark);
            border-left: 4px solid var(--primary);
            padding: 20px;
            border-radius: 8px;
            line-height: 1.6;
        }

        .recommendations-list {
            list-style: none;
        }

        .recommendation-item {
            background: var(--bg-dark);
            padding: 15px;
            border-left: 3px solid var(--primary);
            margin-bottom: 12px;
            border-radius: 6px;
        }

        .recommendation-item::before {
            content: '💡';
            margin-right: 10px;
        }

        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
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
            margin-top: 15px;
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
            .input-group {
                flex-direction: column;
            }
            .analysis-grid {
                grid-template-columns: 1fr;
            }
            .vt-stats {
                grid-template-columns: repeat(2, 1fr);
            }
            .details-grid {
                grid-template-columns: 1fr;
            }
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
                <div class="verdict-title" id="verdictTitle">SAFE</div>
                <div class="verdict-subtitle" id="verdictUrl"></div>
                <div class="risk-level" id="riskLevel">Risk Level: Low</div>
                <div class="confidence-bar-container">
                    <div class="confidence-label">
                        <span>Confidence Score</span>
                        <span id="confidencePercent">0%</span>
                    </div>
                    <div class="confidence-bar">
                        <div class="confidence-fill" id="confidenceFill" style="width: 0%">
                            <span id="confidenceText">0%</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="analysis-grid">
                <div class="analysis-card">
                    <div class="analysis-header">
                        <div class="analysis-icon">🤖</div>
                        <div class="analysis-title">ML Model</div>
                    </div>
                    <div class="analysis-result" id="mlVerdict">-</div>
                    <div class="analysis-detail" id="mlDetail">Pattern-based analysis</div>
                    <div class="analysis-badge" id="mlConfidence">Confidence: -</div>
                </div>

                <div class="analysis-card">
                    <div class="analysis-header">
                        <div class="analysis-icon">🧠</div>
                        <div class="analysis-title">Gemini AI</div>
                    </div>
                    <div class="analysis-result" id="aiVerdict">-</div>
                    <div class="analysis-detail" id="aiDetail">Context-aware threat assessment</div>
                    <div class="analysis-badge" id="aiConfidence">Confidence: -</div>
                </div>

                <div class="analysis-card">
                    <div class="analysis-header">
                        <div class="analysis-icon">🛡️</div>
                        <div class="analysis-title">VirusTotal</div>
                    </div>
                    <div class="analysis-result" id="vtVerdict">-</div>
                    <div class="analysis-detail" id="vtDetail">70+ security vendors</div>
                    <div class="analysis-badge" id="vtBadge">Status: -</div>
                </div>
            </div>

            <div class="section" id="aiSection">
                <div class="section-title">
                    <span class="section-icon">🤖</span>
                    AI Analysis
                </div>
                <div class="ai-explanation" id="aiExplanation"></div>
            </div>

            <div class="section" id="recommendationsSection">
                <div class="section-title">
                    <span class="section-icon">💡</span>
                    Recommendations
                </div>
                <ul class="recommendations-list" id="recommendationsList"></ul>
            </div>

            <div class="section" id="vtSection">
                <div class="section-title">
                    <span class="section-icon">🛡️</span>
                    VirusTotal Scan Results
                </div>
                <div class="vt-stats" id="vtStats"></div>
            </div>

            <div class="section">
                <div class="section-title">
                    <span class="section-icon">🔧</span>
                    Technical Details
                </div>
                <div class="details-grid" id="detailsGrid"></div>
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

        document.getElementById('urlForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const url = document.getElementById('urlInput').value;
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

            const verdict = data.final_verdict;
            document.getElementById('finalVerdict').className = 'final-verdict ' + verdict.toLowerCase();
            const icons = { 'Safe': '✅', 'Suspicious': '⚠️', 'Malicious': '🚨' };
            document.getElementById('verdictIcon').textContent = icons[verdict] || '❓';
            document.getElementById('verdictTitle').textContent = verdict.toUpperCase();
            document.getElementById('verdictUrl').textContent = data.url;
            document.getElementById('riskLevel').textContent = `Risk Level: ${data.risk_level}`;
            document.getElementById('riskLevel').className = 'risk-level risk-' + data.risk_level.toLowerCase();

            const confidence = data.confidence;
            document.getElementById('confidencePercent').textContent = confidence + '%';
            document.getElementById('confidenceFill').style.width = confidence + '%';
            document.getElementById('confidenceText').textContent = confidence + '%';

            const ml = data.details.ml_model;
            document.getElementById('mlVerdict').textContent = ml.verdict;
            document.getElementById('mlDetail').textContent = ml.reason || 'Pattern-based analysis';
            document.getElementById('mlConfidence').textContent = `Confidence: ${ml.confidence}%`;

            if (data.details.ai_analysis && data.details.ai_analysis.available) {
                const ai = data.details.ai_analysis;
                document.getElementById('aiVerdict').textContent = ai.verdict;
                document.getElementById('aiDetail').textContent = 'Context-aware threat assessment';
                document.getElementById('aiConfidence').textContent = `Confidence: ${ai.confidence_score}%`;
                document.getElementById('aiSection').style.display = 'block';
                document.getElementById('aiExplanation').textContent = ai.explanation;

                if (ai.recommendations && ai.recommendations.length > 0) {
                    document.getElementById('recommendationsSection').style.display = 'block';
                    const recList = document.getElementById('recommendationsList');
                    recList.innerHTML = '';
                    ai.recommendations.forEach(rec => {
                        const li = document.createElement('li');
                        li.className = 'recommendation-item';
                        li.textContent = rec;
                        recList.appendChild(li);
                    });
                } else {
                    document.getElementById('recommendationsSection').style.display = 'none';
                }
            } else {
                document.getElementById('aiVerdict').textContent = 'N/A';
                document.getElementById('aiDetail').textContent = 'AI analysis not available';
                document.getElementById('aiConfidence').textContent = 'Not configured';
                document.getElementById('aiSection').style.display = 'none';
                document.getElementById('recommendationsSection').style.display = 'none';
            }

            if (data.details.virustotal && data.details.virustotal.available) {
                const vt = data.details.virustotal;
                document.getElementById('vtVerdict').textContent = vt.verdict;
                document.getElementById('vtDetail').textContent = '70+ security vendors';
                document.getElementById('vtBadge').textContent = `${vt.malicious} malicious detections`;
                document.getElementById('vtSection').style.display = 'block';
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
                document.getElementById('vtVerdict').textContent = 'N/A';
                document.getElementById('vtDetail').textContent = 'VirusTotal not available';
                document.getElementById('vtBadge').textContent = 'Not configured';
                document.getElementById('vtSection').style.display = 'none';
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

# Write to file
with open('Templates/index.html', 'w', encoding='utf-8') as f:
    f.write(html_content)

print("✅ Templates/index.html created successfully!")
print(f"📄 File size: {len(html_content)} characters")
