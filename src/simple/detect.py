import os
import sys
import joblib

# Add project root to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.cleaner import nettoyer_code
from src.simple.classifier import SimpleCWEClassifier

MODEL_PATH = "build/simple/cwe_model.pkl"

def load_model():
    """Load the trained model"""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Run simple/train.py first.")
    
    print("[INFO] Loading trained model...")
    model = SimpleCWEClassifier()
    model.load(MODEL_PATH)
    return model

def predict_file(file_path):
    """Predict CWE for a given file"""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Read and clean code
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        raw_code = f.read()

    cleaned_code = nettoyer_code(raw_code)
    
    # Load model and predict
    model = load_model()
    prediction = model.predict([cleaned_code])
    return prediction[0]

def predict_with_confidence(file_path):
    """Predict CWE with confidence scores"""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        raw_code = f.read()

    cleaned_code = nettoyer_code(raw_code)
    
    model = load_model()
    prediction = model.predict([cleaned_code])[0]
    probabilities = model.predict_proba([cleaned_code])[0]
    
    # Get top 3 predictions with confidence
    classes = model.pipeline.classes_
    top_indices = probabilities.argsort()[-3:][::-1]
    
    results = []
    for i in top_indices:
        results.append({
            'cwe': classes[i],
            'confidence': probabilities[i]
        })
    
    return prediction, results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect.py <file.c>")
        print("Example: python detect.py test_code.c")
        sys.exit(1)
    
    file_path = sys.argv[1]
    try:
        # Simple prediction
        cwe = predict_file(file_path)
        print(f"Detected CWE: {cwe}")
        
        # Detailed prediction with confidence
        print("\nDetailed Analysis:")
        prediction, top_predictions = predict_with_confidence(file_path)
        
        for i, result in enumerate(top_predictions, 1):
            confidence_pct = result['confidence'] * 100
            print(f"  {i}. {result['cwe']} - {confidence_pct:.2f}% confidence")
            
    except Exception as e:
        print(f"Error: {e}")