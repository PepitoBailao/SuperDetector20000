import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.utils.dataset import create_clean_dataset
from src.simple.train import SimpleCWEClassifier

def setup_dataset():
    print("[1/4] Setting up dataset...")
    csv_path = "datasets/dataset.csv"
    
    if os.path.exists(csv_path):
        print("✓ Dataset already exists")
        return True
    
    try:
        print("Creating new dataset from sources...")
        create_clean_dataset(csv_path)
        print("✓ Dataset created successfully")
        return True
    except Exception as e:
        print(f"✗ Dataset creation failed: {e}")
        return False

def train_model():
    print("[2/4] Training model...")
    model_path = "build/simple/cwe_model.pkl"
    
    # Archive previous model if exists
    try:
        from stats.old_stat import archive_current_stats
        archive_current_stats()
        print("✓ Previous model archived")
    except:
        pass
    
    csv_path = "datasets/dataset.csv"
    if not os.path.exists(csv_path):
        print("✗ No dataset found")
        return False
    
    try:
        print("Training classifier...")
        model = SimpleCWEClassifier()
        model.train_from_csv(csv_path)
        model.save(model_path)
        
        print(f"✓ Model trained successfully")
        print(f"  Accuracy: {model.accuracy_:.1%}")
        print(f"  F1-Score: {model.f1_score_:.3f}")
        return True
    except Exception as e:
        print(f"✗ Model training failed: {e}")
        return False

def validate_model():
    print("[3/4] Validating model...")
    model_path = "build/simple/cwe_model_latest.pkl"
    
    if not os.path.exists(model_path):
        print("✗ No model found to validate")
        return False
    
    try:
        model = SimpleCWEClassifier.load_model(model_path)
        
        # Test with different code samples
        test_codes = [
            "int main() { return 0; }",
            "char buf[10]; strcpy(buf, user_input);",
            "if (password == stored_password) { authenticate(); }"
        ]
        
        predictions = model.predict(test_codes)
        print("✓ Model validation successful")
        print(f"  Test predictions: {', '.join(predictions)}")
        return True
    except Exception as e:
        print(f"✗ Model validation failed: {e}")
        return False

def generate_statistics():
    print("[4/4] Generating statistics...")
    try:
        from stats.all_stat import calculate_and_save_statistics
        result = calculate_and_save_statistics()
        if result:
            print("✓ Statistics generated successfully")
        else:
            print("✗ Statistics generation failed")
        return result
    except Exception as e:
        print(f"✗ Statistics generation failed: {e}")
        return False

def detect_menu():
    model_path = "build/simple/cwe_model_latest.pkl"
    if not os.path.exists(model_path):
        print("No model found. Run setup first.")
        return
    
    print("\n=== CWE Detection Menu ===")
    print("1. Test file  2. Test code  3. Archive  4. Exit")
    
    while True:
        try:
            choice = input("\nChoice: ").strip()
            
            if choice == "1":
                print("--- Test File ---")
                file_path = input("File path: ").strip()
                if file_path:
                    try:
                        from src.simple.train import SimpleCWEClassifier, read_file, clean_code
                        model = SimpleCWEClassifier.load_model(model_path)
                        
                        raw_code = read_file(file_path)
                        cleaned_code = clean_code(raw_code)
                        prediction = model.predict([cleaned_code])[0]
                        
                        print(f"Detected: {prediction}")
                        
                        probabilities = model.predict_proba([cleaned_code])[0]
                        classes = model.pipeline.classes_
                        top_indices = probabilities.argsort()[-3:][::-1]
                        
                        print("Top predictions:")
                        for i in top_indices:
                            confidence = probabilities[i] * 100
                            print(f"  {classes[i]} - {confidence:.1f}%")
                            
                    except Exception as e:
                        print(f"Error: {e}")
                        
            elif choice == "2":
                print("--- Test Code Snippet ---")
                print("Paste code (type 'END' to finish):")
                lines = []
                while True:
                    try:
                        line = input()
                        if line.strip().upper() == "END":
                            break
                        lines.append(line)
                    except EOFError:
                        break
                
                if lines:
                    try:
                        from src.simple.train import SimpleCWEClassifier, clean_code
                        model = SimpleCWEClassifier.load_model(model_path)
                        
                        cleaned_code = clean_code("\n".join(lines))
                        prediction = model.predict([cleaned_code])[0]
                        
                        print(f"Detected: {prediction}")
                        
                        probabilities = model.predict_proba([cleaned_code])[0]
                        classes = model.pipeline.classes_
                        top_indices = probabilities.argsort()[-3:][::-1]
                        
                        print("Top predictions:")
                        for i in top_indices:
                            confidence = probabilities[i] * 100
                            print(f"  {classes[i]} - {confidence:.1f}%")
                            
                    except Exception as e:
                        print(f"Error: {e}")
            
            elif choice == "3":
                print("--- Archive Model ---")
                try:
                    from stats.old_stat import archive_current_stats
                    archive_current_stats()
                    print("Archived")
                except:
                    print("Archive failed")
                    
            elif choice in ["4", "exit", "quit"]:
                print("Exiting...")
                break
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break

def main():
    print("=== SuperDetector20000 ===")
    print("Starting pipeline...")
    
    steps = [setup_dataset, train_model, validate_model, generate_statistics]
    
    for step in steps:
        if not step():
            print("Pipeline failed")
            sys.exit(1)
    
    print("\n✓ Setup completed successfully!")
    
    choice = input("\nStart detection menu? (y/n): ")
    if choice.lower() == 'y':
        detect_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)