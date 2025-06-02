import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.utils.dataset import download_and_extract, check_dataset_exists
from src.utils.parser import parse_juliet_to_csv
from src.simple.train import SimpleCWEClassifier

def print_step(step, description):
    print(f"\n[{step}/6] {description}")
    print("-" * 30)

def setup_dataset():
    print_step(1, "Setup dataset")
    if check_dataset_exists():
        print("Dataset found")
        return True
    
    try:
        extracted_path = download_and_extract()
        print("Dataset ready")
        return True
    except Exception as e:
        print(f"Download failed: {e}")
        return False

def parse_dataset():
    print_step(2, "Parse dataset")
    csv_path = "datasets/juliet_cwe_dataset.csv"
    
    if os.path.exists(csv_path):
        print("CSV found")
        return True
    
    root_dir = "datasets/juliet/extracted/C/testcases"
    if not os.path.exists(root_dir):
        print("Missing source")
        return False
    
    try:
        parse_juliet_to_csv(root_dir, csv_path)
        print("CSV created")
        return True
    except Exception as e:
        print(f"Parse failed: {e}")
        return False

def train_model():
    print_step(3, "Train model")
    model_path = "build/simple/cwe_model.pkl"
    
    # Archive le modèle précédent avant d'entraîner le nouveau
    try:
        from stats.old_stat import archive_current_stats
        archive_current_stats()
    except Exception as e:
        print(f"Archive warning: {e}")
    
    csv_path = "datasets/juliet_cwe_dataset.csv"
    if not os.path.exists(csv_path):
        print("CSV not found")
        return False
    
    try:
        print("Training new model...")
        model = SimpleCWEClassifier()
        model.train_from_csv(csv_path, test_size=0.1)
        saved_path = model.save(model_path)
        print(f"New model saved: {saved_path}")
        return True
    except Exception as e:
        print(f"Training failed: {e}")
        return False

def validate_model():
    print_step(4, "Validate model")
    model_path = "build/simple/cwe_model_latest.pkl"
    
    if not os.path.exists(model_path):
        print("Latest model not found")
        return False
    
    try:
        model = SimpleCWEClassifier.load_model(model_path)
        prediction = model.predict(["int main() { return 0; }"])
        print(f"Model validated (test: {prediction[0]})")
        return True
    except Exception as e:
        print(f"Validation failed: {e}")
        return False

def generate_statistics():
    print_step(5, "Generate statistics")
    try:
        from stats.all_stat import calculate_and_save_statistics
        return calculate_and_save_statistics()
    except Exception as e:
        print(f"Statistics failed: {e}")
        return False

def update_archives():
    print_step(6, "Update archives")
    try:
        from stats.old_stat import generate_archives_index
        index_path = generate_archives_index()
        if index_path:
            print("Archives index updated")
            return True
        else:
            print("No archives to index")
            return True
    except Exception as e:
        print(f"Archives update failed: {e}")
        return False

def detect_menu():
    model_path = "build/simple/cwe_model_latest.pkl"
    if not os.path.exists(model_path):
        print("No trained model found. Run setup first.")
        return
    
    print("\n" + "=" * 50)
    print("CWE Detection Menu")
    print("=" * 50)
    print("1. Test file")
    print("2. Test code snippet")
    print("3. Archive current model")
    print("4. Exit")
    
    while True:
        try:
            choice = input("\nChoice (1-4): ").strip()
            
            if choice in ["1", "1."]:
                file_path = input("File path: ").strip()
                if not file_path:
                    continue
                    
                try:
                    from src.simple.train import SimpleCWEClassifier, read_file, clean_code
                    model = SimpleCWEClassifier.load_model(model_path)
                    
                    raw_code = read_file(file_path)
                    cleaned_code = clean_code(raw_code)
                    prediction = model.predict([cleaned_code])[0]
                    
                    print(f"\nFile: {file_path}")
                    print(f"Detected CWE: {prediction}")
                    
                    probabilities = model.predict_proba([cleaned_code])[0]
                    classes = model.pipeline.classes_
                    top_indices = probabilities.argsort()[-3:][::-1]
                    
                    print("Top predictions:")
                    for i in top_indices:
                        confidence = probabilities[i] * 100
                        print(f"  {classes[i]} - {confidence:.1f}%")
                        
                except Exception as e:
                    print(f"Error: {e}")
                    
            elif choice in ["2", "2."]:
                print("Paste code (type 'END' on new line to finish):")
                lines = []
                while True:
                    try:
                        line = input()
                        if line.strip().upper() == "END":
                            break
                        lines.append(line)
                    except EOFError:
                        break
                
                if not lines:
                    print("No code provided")
                    continue
                    
                code = "\n".join(lines)
                
                try:
                    from src.simple.train import SimpleCWEClassifier, clean_code
                    model = SimpleCWEClassifier.load_model(model_path)
                    
                    cleaned_code = clean_code(code)
                    prediction = model.predict([cleaned_code])[0]
                    
                    print(f"\nDetected CWE: {prediction}")
                    
                    probabilities = model.predict_proba([cleaned_code])[0]
                    classes = model.pipeline.classes_
                    top_indices = probabilities.argsort()[-3:][::-1]
                    
                    print("Top predictions:")
                    for i in top_indices:
                        confidence = probabilities[i] * 100
                        print(f"  {classes[i]} - {confidence:.1f}%")
                        
                except Exception as e:
                    print(f"Error: {e}")
            
            elif choice in ["3", "3."]:
                try:
                    from stats.old_stat import archive_current_stats
                    archive_path = archive_current_stats()
                    if archive_path:
                        print("Model archived successfully")
                    else:
                        print("Nothing to archive")
                except Exception as e:
                    print(f"Archive error: {e}")
                    
            elif choice in ["4", "4.", "exit", "quit", "q"]:
                break
            else:
                print(f"Invalid choice: '{choice}'. Please enter 1, 2, 3, or 4.")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except EOFError:
            print("\nExiting...")
            break

def main():
    start_time = time.time()
    print("SuperDetector20000 - CWE Detection")
    print("=" * 50)
    
    steps = [setup_dataset, parse_dataset, train_model, validate_model, generate_statistics, update_archives]
    
    for step in steps:
        if not step():
            print("Pipeline failed")
            sys.exit(1)
    
    elapsed_time = time.time() - start_time
    print(f"\nSetup completed ({elapsed_time:.1f}s)")
    
    print("\nOptions:")
    print("1. Start detection menu")
    print("2. Exit")
    
    choice = input("\nChoice (1-2): ").strip()
    if choice == "1":
        detect_menu()
    
    print("Usage: python src/simple/detect.py file.c")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)