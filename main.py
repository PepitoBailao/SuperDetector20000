import os
import sys
import time

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.utils.dataset import download_and_extract, check_dataset_exists
from src.utils.parser import parse_juliet_to_csv

def print_header():
    """Print welcome header"""
    print("="*60)
    print("SuperDetector20000 - CWE Detection System")
    print("AI-powered vulnerability detection for C/C++ code")
    print("="*60)

def print_step(step_num, total_steps, description):
    """Print current step"""
    print(f"\n[{step_num}/{total_steps}] {description}")
    print("-" * 50)

def setup_dataset():
    """Setup Juliet dataset"""
    print_step(1, 4, "Setting up Juliet dataset")
    
    if check_dataset_exists():
        print("Dataset already exists at: datasets/juliet/extracted")
        return True
    else:
        print("Downloading Juliet dataset (this may take a while)...")
        try:
            extracted_path = download_and_extract()
            print(f"Dataset ready at: {extracted_path}")
            return True
        except Exception as e:
            print(f"Error downloading dataset: {e}")
            return False

def parse_dataset():
    """Parse dataset to CSV"""
    print_step(2, 4, "Parsing dataset to CSV")
    
    csv_path = "datasets/juliet_cwe_dataset.csv"
    
    if os.path.exists(csv_path):
        print(f"CSV already exists at: {csv_path}")
        return True
    
    root_dir = "datasets/juliet/extracted/C/testcases"
    if not os.path.exists(root_dir):
        print(f"Testcases directory not found: {root_dir}")
        return False
    
    try:
        print("Parsing C/C++ files...")
        parse_juliet_to_csv(root_dir, csv_path)
        print(f"CSV dataset created: {csv_path}")
        return True
    except Exception as e:
        print(f"Error parsing dataset: {e}")
        return False

def train_model():
    """Train the CWE detection model"""
    print_step(3, 4, "Training CWE detection model")
    
    model_path = "build/simple/cwe_model.pkl"
    
    if os.path.exists(model_path):
        print(f"Model already exists at: {model_path}")
        print("To retrain, delete the model file and run again.")
        return True
    
    try:
        # Import here to avoid issues if dependencies missing
        from src.simple.classifier import SimpleCWEClassifier
        import pandas as pd
        
        csv_path = "datasets/juliet_cwe_dataset.csv"
        if not os.path.exists(csv_path):
            print(f"CSV dataset not found: {csv_path}")
            return False
        
        print("Loading dataset...")
        model = SimpleCWEClassifier(max_features=5000)
        model.train_from_csv(csv_path, test_size=0.2)
        
        print("Saving model...")
        model.save(model_path)
        print(f"Model trained and saved to: {model_path}")
        return True
        
    except Exception as e:
        print(f"Error training model: {e}")
        return False

def show_usage():
    """Show usage instructions"""
    print_step(4, 4, "Setup Complete!")
    
    print("Your CWE detection system is ready!")
    print("\nUsage Instructions:")
    print("-" * 30)
    print("Detect CWE in a file:")
    print("   python src/simple/detect.py your_code.c")
    print()
    print("Example files to test:")
    print("   python src/simple/detect.py datasets/juliet/extracted/C/testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_01_bad.c")
    print()
    print("Advanced options:")
    print("   - Retrain model: Delete build/simple/cwe_model.pkl and run main.py again")
    print("   - Multi-label detection: Use src/multilabel/ scripts")
    print()
    print("For more info, check README.md")

def main():
    """Main orchestrator function"""
    start_time = time.time()
    
    print_header()
    
    # Step 1: Setup dataset
    if not setup_dataset():
        print("\nFailed to setup dataset. Exiting.")
        sys.exit(1)
    
    # Step 2: Parse dataset  
    if not parse_dataset():
        print("\nFailed to parse dataset. Exiting.")
        sys.exit(1)
    
    # Step 3: Train model
    if not train_model():
        print("\nFailed to train model. Exiting.")
        sys.exit(1)
    
    # Step 4: Show usage
    show_usage()
    
    # Summary
    elapsed_time = time.time() - start_time
    print(f"\nTotal setup time: {elapsed_time:.1f} seconds")
    print("SuperDetector20000 is ready to detect vulnerabilities!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)