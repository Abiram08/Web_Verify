html_content = '''<!DOCTYPE html>
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
</html>
'''

with open('Templates/index.html', 'w', encoding='utf-8') as f:
    f.write(html_content)

print("✅ Templates/index.html created successfully with improved UI!")
