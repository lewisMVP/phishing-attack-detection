import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os

# --- CONFIGURATION ---
INPUT_FILE = '../../data/datasets/url_features_dataset.csv'
MODEL_DIR = '../../src/models/saved_models/'
MODEL_PATH = os.path.join(MODEL_DIR, 'url_random_forest.pkl')

# Create directory for saving models
os.makedirs(MODEL_DIR, exist_ok=True)

def train_model():
    print("1. Loading dataset...")
    if not os.path.exists(INPUT_FILE):
        print(f"Error: Dataset not found at {INPUT_FILE}")
        return

    df = pd.read_csv(INPUT_FILE)
    
    # Handle missing values (if any)
    df = df.fillna(0)
    
    print(f"   Data shape: {df.shape}")
    print(f"   Phishing samples: {len(df[df['label'] == 1])}")
    print(f"   Benign samples: {len(df[df['label'] == 0])}")

    # 2. Prepare Data
    # Drop non-numeric columns (URL string) and the target label
    X = df.drop(['url', 'label'], axis=1) 
    y = df['label']

    # Split into Training (80%) and Testing (20%) sets
    print("\n2. Splitting data (80% Train, 20% Test)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Initialize and Train Model
    print("\n3. Training Random Forest Classifier...")
    # n_estimators=100 means we use 100 decision trees
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)
    print("   Training completed!")

    # 4. Evaluation
    print("\n4. Evaluating model...")
    y_pred = rf_model.predict(X_test)

    # Calculate metrics
    acc = accuracy_score(y_test, y_pred)
    print(f"   >>> ACCURACY: {acc * 100:.2f}%")
    
    print("\n   Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign (0)', 'Phishing (1)']))

    print("   Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # 5. Save the Model
    print(f"\n5. Saving model to {MODEL_PATH}...")
    joblib.dump(rf_model, MODEL_PATH)
    print("   Model saved successfully! You can now use it for prediction.")

if __name__ == "__main__":
    train_model()