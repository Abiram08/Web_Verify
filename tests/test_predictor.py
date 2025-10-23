import numpy as np
import types

from predictor import extract_features, predict_url


def test_extract_features_shape_and_types():
    url = 'http://example.com/path?query=1'
    features = extract_features(url)
    assert isinstance(features, np.ndarray)
    assert features.shape[0] == 1
    assert features.shape[1] == 6


def test_predict_url_with_dummy_model():
    # Create a dummy model with a predict method
    class DummyModel:
        def predict(self, X):
            # Return 1 for length < 50, else 0
            return np.array([1 if x[0] < 50 else 0 for x in X])

    model = DummyModel()
    short_url = 'http://example.com/'
    long_url = 'http://' + 'a' * 200

    assert predict_url(model, short_url) == 'Legitimate'
    assert predict_url(model, long_url) == 'Phishing'
