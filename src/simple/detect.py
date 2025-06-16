import os
import re
import sys

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.simple.train import SimpleCWEClassifier

def clean_code(code):
    """Clean code by removing comments and normalizing whitespace"""
    code = re.sub(r'//.*?$|/\*.*?\*/', '', code, flags=re.MULTILINE | re.DOTALL)
    return re.sub(r'\s+', ' ', code).strip()

def read_file(file_path):
    """Read file with proper encoding handling"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()

def detect_cwe_in_file(file_path, model_path="build/simple/cwe_model_latest.pkl"):
    """Detect CWE in a single file"""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    model = SimpleCWEClassifier.load_model(model_path)
    raw_code = read_file(file_path)
    cleaned_code = clean_code(raw_code)
    
    predictions, confidences = model.predict_with_postprocessing([cleaned_code])
    prediction = predictions[0]
    confidence = confidences[0]
    
    # Get top 3 predictions
    probabilities = model.predict_proba([cleaned_code])[0]
    classes = model.pipeline.classes_
    top_indices = probabilities.argsort()[-3:][::-1]
    
    top_predictions = []
    for i in top_indices:
        top_predictions.append({
            'cwe': classes[i],
            'confidence': probabilities[i]
        })
    
    return {
        'primary_prediction': prediction,
        'primary_confidence': confidence,
        'top_predictions': top_predictions,
        'file_path': file_path
    }

def detect_cwe_in_code(code_snippet, model_path="build/simple/cwe_model_latest.pkl"):
    """Detect CWE in code snippet"""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")
    
    model = SimpleCWEClassifier.load_model(model_path)
    cleaned_code = clean_code(code_snippet)
    
    predictions, confidences = model.predict_with_postprocessing([cleaned_code])
    prediction = predictions[0]
    confidence = confidences[0]
    
    # Get top 3 predictions
    probabilities = model.predict_proba([cleaned_code])[0]
    classes = model.pipeline.classes_
    top_indices = probabilities.argsort()[-3:][::-1]
    
    top_predictions = []
    for i in top_indices:
        top_predictions.append({
            'cwe': classes[i],
            'confidence': probabilities[i]
        })
    
    return {
        'primary_prediction': prediction,
        'primary_confidence': confidence,
        'top_predictions': top_predictions,
        'code_snippet': code_snippet
    }

def detect_cwe_in_directory(directory_path, model_path="build/simple/cwe_model_latest.pkl", file_extensions=None):
    """Detect CWE in all files in a directory"""
    if file_extensions is None:
        file_extensions = ['.c', '.cpp', '.h', '.hpp', '.java', '.py', '.js', '.cs']
    
    results = []
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if any(file.lower().endswith(ext) for ext in file_extensions):
                file_path = os.path.join(root, file)
                try:
                    result = detect_cwe_in_file(file_path, model_path)
                    results.append(result)
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
    
    return results

def print_detection_results(results):
    """Print detection results in a formatted way"""
    if isinstance(results, dict):
        results = [results]
    
    for result in results:
        print(f"\n--- Detection Results ---")
        if 'file_path' in result:
            print(f"File: {result['file_path']}")
        
        print(f"Primary Prediction: {result['primary_prediction']}")
        print(f"Primary Confidence: {result['primary_confidence']:.1%}")
        
        print("Top Predictions:")
        for pred in result['top_predictions']:
            print(f"  {pred['cwe']}: {pred['confidence']:.1%}")

if __name__ == "__main__":
    # Test detection functionality
    model_path = "build/simple/cwe_model_latest.pkl"
    
    if not os.path.exists(model_path):
        print("No model found. Train a model first.")
        exit(1)
    
    # Test with sample code
    test_code = """
    char buffer[10];
    strcpy(buffer, user_input);
    """
    
    print("Testing CWE detection...")
    result = detect_cwe_in_code(test_code, model_path)
    print_detection_results(result)