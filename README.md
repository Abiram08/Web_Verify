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
