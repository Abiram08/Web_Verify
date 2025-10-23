import joblib
import numpy as np
from urllib.parse import urlparse
import os

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')

def load_model(path=MODEL_PATH):
    """Load and return the ML model from disk."""
    return joblib.load(path)

def extract_features(url: str) -> np.ndarray:
    """Extract simple numerical features from a URL.

    Returns a 1xN numpy array suitable for model.predict.
    """
    parsed = urlparse(url)
    domain_name = parsed.netloc
    path = parsed.path
    query = parsed.query
    features = [
        len(url),
        domain_name.count('.'),
        len(domain_name),
        url.count('/'),
        len(path),
        len(query),
    ]
    return np.array(features).reshape(1, -1)

def predict_url(model, url: str) -> str:
    """Predict whether a URL is 'Legitimate' or 'Phishing'.

    Returns the label string.
    """
    features = extract_features(url)
    pred = model.predict(features)
    return 'Legitimate' if pred[0] == 1 else 'Phishing'
