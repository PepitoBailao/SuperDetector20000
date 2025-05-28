import os
import sys

# Add parent directories to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.simple.classifier import SimpleCWEClassifier
from src.utils.parser import parse_juliet_to_csv

def train_simple_model_from_csv():
    print("[INFO] Training simple CWE classifier from CSV...")
    
    # Check if CSV exists, if not create it
    csv_path = "datasets/juliet_cwe_dataset.csv"
    
    if not os.path.exists(csv_path):
        print("[INFO] CSV dataset not found, parsing Juliet dataset...")
        data_path = "datasets/juliet/extracted/C/testcases"
        
        if not os.path.exists(data_path):
            print("[ERROR] Juliet dataset not found. Run utils/dataset.py first.")
            return
        
        parse_juliet_to_csv(data_path, csv_path)
    
    # Train model from CSV
    model = SimpleCWEClassifier(max_features=5000)
    model.train_from_csv(csv_path, test_size=0.2)
    
    # Save model
    model.save("build/simple/cwe_model.pkl")
    print("[INFO] Training complete!")

if __name__ == "__main__":
    train_simple_model_from_csv()