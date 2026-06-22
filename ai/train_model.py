import numpy as np
import os
import joblib


def generate_training_data(n_samples=500):
    np.random.seed(42)
    X = np.random.rand(n_samples, 6)
    weights = [0.30, 0.20, 0.20, 0.10, 0.10, 0.10]
    y = np.dot(X, weights)
    y = np.clip(y, 0, 1)
    return X, y


def train_model():
    from sklearn.ensemble import GradientBoostingRegressor
    X, y = generate_training_data()
    model = GradientBoostingRegressor(n_estimators=100, random_state=42)
    model.fit(X, y)
    model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'risk_model.pkl')
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    print(f'Model saved to {model_path}')
    return model


if __name__ == '__main__':
    train_model()
