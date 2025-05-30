import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.simple.train import SimpleCWEClassifier, clean_code, read_file

MODEL_PATH = "build/simple/cwe_model.pkl"

def predict_file(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    raw_code = read_file(file_path)
    cleaned_code = clean_code(raw_code)
    model = SimpleCWEClassifier.load_model(MODEL_PATH)
    return model.predict([cleaned_code])[0]

def predict_with_confidence(file_path):
    raw_code = read_file(file_path)
    cleaned_code = clean_code(raw_code)
    model = SimpleCWEClassifier.load_model(MODEL_PATH)
    
    prediction = model.predict([cleaned_code])[0]
    probabilities = model.predict_proba([cleaned_code])[0]
    classes = model.pipeline.classes_
    top_indices = probabilities.argsort()[-3:][::-1]
    
    results = [{'cwe': classes[i], 'confidence': probabilities[i]} for i in top_indices]
    return prediction, results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect.py <file.c>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    try:
        print(f"Analyzing: {file_path}")
        cwe = predict_file(file_path)
        print(f"Detected CWE: {cwe}")
        
        print("Top predictions:")
        _, top_predictions = predict_with_confidence(file_path)
        
        for i, result in enumerate(top_predictions, 1):
            confidence = result['confidence'] * 100
            print(f"  {i}. {result['cwe']} - {confidence:.2f}%")
            
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)