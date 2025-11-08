# ML Legitimacy Website Checker

Simple Flask app that predicts whether a URL is legitimate or phishing using a pre-trained model.

Quickstart
1. Create a virtual environment: python -m venv .venv
2. Activate it: .venv\Scripts\Activate.ps1
3. Install dependencies: pip install -r requirements.txt
4. Run the app: python app.py

Files
- `app.py` - Flask web application (uses `predictor.py` for predictions)
- `predictor.py` - Feature extraction and model wrapper
- `model.pkl` - Pretrained model (not modified)
- `tests/` - Unit tests

## Streamlit AI + VirusTotal app (optional)

This repository also supports an optional Streamlit-based UI that integrates OpenAI and VirusTotal for a richer, heuristic + reputation based phishing URL analysis. The Flask app remains the primary lightweight predictor. The Streamlit app is provided as an additional tool and requires extra dependencies and API keys.

Quickstart (Streamlit)
1. Create a virtual environment: `python -m venv .venv`
2. Activate it (PowerShell): `.venv\Scripts\Activate.ps1`
3. Install Streamlit-specific dependencies: `pip install -r requirements-streamlit.txt`
4. Run the Streamlit app (save the Streamlit code to `streamlit_app.py` in the repo root):

```powershell
streamlit run streamlit_app.py
```

Secrets / API keys
- The Streamlit app expects `OPENAI_API_KEY` and `VIRUSTOTAL_API_KEY` to be provided either via Streamlit secrets (create `.streamlit/secrets.toml`) or environment variables.
- A sample example file is provided at `.streamlit/secrets.toml.example` — DO NOT commit real keys.

Notes and safety
- The Streamlit UI sends URL data to third-party services (OpenAI, VirusTotal). Avoid submitting private/internal URLs or secrets.
- VirusTotal has rate limits and quotas; batch scans may be slow. The app includes simple polling and delays, but monitor your key's quota.
- The Streamlit app stores analysis history locally in SQLite. Raw AI responses may contain user-submitted data; if you store logs or history in shared environments, consider redaction or opt-in storage.

If you prefer to keep only the Flask app, continue to use the existing `requirements.txt` and `app.py` as before.
