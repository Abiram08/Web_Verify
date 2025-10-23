from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
from urllib.parse import urlparse
import webbrowser

app = Flask(__name__)

# Load the trained model (Make sure you have a trained model at the provided path)
model = joblib.load('model.pkl')  # Change this path to where your model is saved

# Feature extraction function (Ensure it generates 6 features as expected by the model)
def extract_features(url):
    parsed_url = urlparse(url)
    domain_name = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query
    features = [
        len(url),  # Length of the URL
        domain_name.count('.'),  # Count of '.' in the domain (subdomains)
        len(domain_name),  # Length of the domain name
        url.count('/'),  # Count of '/' in the URL
        len(path),  # Length of the URL path
        len(query)  # Length of the query string
    ]
    return np.array(features).reshape(1, -1)

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
        # Extract features from the URL
        features = extract_features(url)
        
        # Make the prediction using the loaded model
        prediction = model.predict(features)

        # Determine the result
        result = 'Legitimate' if prediction[0] == 1 else 'Phishing'
        return jsonify({'prediction': result})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Open the web browser automatically
    webbrowser.open('http://127.0.0.1:5000/')
    app.run(debug=True)
