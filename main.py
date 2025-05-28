import os
import sys
import time

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.utils.dataset import download_and_extract, check_dataset_exists
from src.utils.parser import parse_juliet_to_csv

def print_header():
    """Print welcome header"""
    print("="*50)
    print("SuperDetector20000 - CWE Detection")
    print("="*50)

def print_step(step_num, total_steps, description):
    """Print current step"""
    print(f"\n[{step_num}/{total_steps}] {description}")
    print("-" * 30)

def setup_dataset():
    """Setup Juliet dataset"""
    print_step(1, 4, "Setup dataset")
    
    if check_dataset_exists():
        print("Dataset found")
        return True
    else:
        print("Downloading dataset...")
        try:
            extracted_path = download_and_extract()
            print(f"Dataset ready: {extracted_path}")
            return True
        except Exception as e:
            print(f"Download failed: {e}")
            return False

def parse_dataset():
    """Parse dataset to CSV"""
    print_step(2, 4, "Parse dataset")
    
    csv_path = "datasets/juliet_cwe_dataset.csv"
    
    if os.path.exists(csv_path):
        print("CSV found")
        return True
    
    root_dir = "datasets/juliet/extracted/C/testcases"
    if not os.path.exists(root_dir):
        print(f"Missing: {root_dir}")
        return False
    
    try:
        print("Processing files...")
        parse_juliet_to_csv(root_dir, csv_path)
        print("CSV created")
        return True
    except Exception as e:
        print(f"Parse failed: {e}")
        return False

def train_model():
    """Train the CWE detection model"""
    print_step(3, 4, "Train model")
    
    model_path = "build/simple/cwe_model.pkl"
    
    if os.path.exists(model_path):
        print("Model found")
        return True
    
    try:
        from src.simple.classifier import SimpleCWEClassifier
        import pandas as pd
        
        csv_path = "datasets/juliet_cwe_dataset.csv"
        if not os.path.exists(csv_path):
            print("CSV not found")
            return False
        
        print("Training...")
        model = SimpleCWEClassifier(max_features=5000)
        model.train_from_csv(csv_path, test_size=0.2)
        
        print("Saving...")
        model.save(model_path)
        print("Model saved")
        return True
        
    except Exception as e:
        print(f"Training failed: {e}")
        return False

def show_usage():
    """Show usage instructions"""
    print_step(4, 4, "Complete")
    
    print("System ready!")
    print("\nUsage:")
    print("  python src/simple/detect.py file.c")
    print()
    print("Options:")
    print("  - Retrain: Delete build/simple/cwe_model.pkl")
    print("  - Clean all: python src/utils/nettoyeur_de_dossier.py")

def main():
    """Main function"""
    start_time = time.time()
    
    print_header()
    
    # Step 1: Setup dataset
    if not setup_dataset():
        print("\nSetup failed")
        sys.exit(1)
    
    # Step 2: Parse dataset  
    if not parse_dataset():
        print("\nParse failed")
        sys.exit(1)
    
    # Step 3: Train model
    if not train_model():
        print("\nTraining failed")
        sys.exit(1)
    
    # Step 4: Show usage
    show_usage()
    
    # Summary
    elapsed_time = time.time() - start_time
    print(f"\nTime: {elapsed_time:.1f}s")
    print("Ready!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)