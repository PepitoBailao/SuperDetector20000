import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.cleaner import nettoyer_code
from src.simple.classifier import SimpleCWEClassifier

MODEL_PATH = "build/simple/cwe_model.pkl"
SUPPORTED_EXTENSIONS = {'.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'}

def is_supported_language(file_path):
    _, ext = os.path.splitext(file_path.lower())
    return ext in SUPPORTED_EXTENSIONS

def detect_language_by_content(code_content):
    indicators = ['#include', 'printf', 'scanf', 'malloc', 'free', 'int main', 
                 'void main', 'struct', 'typedef', 'char *', 'char*', 'NULL', 
                 'nullptr', '->', '/*', '*/', 'std::']
    return sum(1 for indicator in indicators if indicator in code_content) >= 2

def validate_file_language(file_path):
    if not is_supported_language(file_path):
        _, ext = os.path.splitext(file_path)
        raise ValueError(f"Unsupported file type '{ext}'. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}")
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        raise ValueError(f"Cannot read file {file_path}: {e}")
    
    if not detect_language_by_content(content):
        print("WARNING: File may not contain C/C++ code")
    
    return content

def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}")
    return SimpleCWEClassifier.load_model(MODEL_PATH)

def predict_file(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    raw_code = validate_file_language(file_path)
    cleaned_code = nettoyer_code(raw_code)
    model = load_model()
    return model.predict([cleaned_code])[0]

def predict_with_confidence(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    raw_code = validate_file_language(file_path)
    cleaned_code = nettoyer_code(raw_code)
    model = load_model()
    
    prediction = model.predict([cleaned_code])[0]
    probabilities = model.predict_proba([cleaned_code])[0]
    classes = model.pipeline.classes_
    top_indices = probabilities.argsort()[-3:][::-1]
    
    results = [{'cwe': classes[i], 'confidence': probabilities[i]} for i in top_indices]
    return prediction, results

def show_supported_languages():
    print("SuperDetector20000 - Supported Languages")
    print("=" * 40)
    print("C/C++ vulnerability detection only.")
    print(f"Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect.py <file.c>")
        show_supported_languages()
        sys.exit(1)
    
    if sys.argv[1] in ['--help', '-h']:
        show_supported_languages()
        sys.exit(0)
    
    file_path = sys.argv[1]
    try:
        print(f"Analyzing: {file_path}")
        
        cwe = predict_file(file_path)
        print(f"Detected CWE: {cwe}")
        
        print("\nTop predictions:")
        _, top_predictions = predict_with_confidence(file_path)
        
        for i, result in enumerate(top_predictions, 1):
            confidence = result['confidence'] * 100
            print(f"  {i}. {result['cwe']} - {confidence:.2f}%")
            
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)