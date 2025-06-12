import os
import sys
import time
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from src.utils.dataset import create_clean_dataset
from src.simple.train import SimpleCWEClassifier

def setup_cwe_api():
    """Setup CWE API database"""
    print("[0/4] Setting up CWE API database...")
    try:
        from src.utils.cwe_api import update_cwe_database
        db_path = update_cwe_database()
        print("✓ CWE API database updated successfully")
        return True
    except Exception as e:
        print(f"⚠ CWE API setup failed: {e}")
        print("  Continuing without API data...")
        return False

def setup_dataset():
    """Setup dataset from multiple sources"""
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
    """Train the CWE classification model"""
    print("[2/4] Training model...")
    model_path = "build/simple/cwe_model.pkl"
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
    """Validate the trained model"""
    print("[3/4] Validating model...")
    model_path = "build/simple/cwe_model_latest.pkl"
    if not os.path.exists(model_path):
        print("✗ No model found to validate")
        return False
    
    try:
        model = SimpleCWEClassifier.load_model(model_path)
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
    """Generate comprehensive statistics"""
    print("[4/4] Generating statistics...")
    try:
        from stats.all_stat import generate_enhanced_statistics
        result = generate_enhanced_statistics()
        if result:
            print("✓ Enhanced statistics generated successfully")
        else:
            print("✗ Statistics generation failed")
        return result
    except Exception as e:
        print(f"✗ Statistics generation failed: {e}")
        return False

def show_cwe_details(cwe_name):
    """Show detailed CWE information from API"""
    try:
        from src.utils.cwe_api import get_cwe_info
        cwe_id = int(cwe_name.replace('CWE', ''))
        cwe_info = get_cwe_info(cwe_id)
        
        print(f"\n--- {cwe_name} Details ---")
        print(f"Name: {cwe_info.get('name', 'Unknown')}")
        
        description = cwe_info.get('description', 'No description available')
        if len(description) > 200:
            description = description[:200] + "..."
        print(f"Description: {description}")
        
        parents = cwe_info.get('parents', [])
        if parents:
            print(f"Parents: {', '.join(map(str, parents))}")
        
        children = cwe_info.get('children', [])
        if children:
            print(f"Children: {', '.join(map(str, children))}")
        
        examples = cwe_info.get('code_examples', [])
        if examples:
            print(f"Code examples available: {len(examples)}")
            
    except Exception as e:
        print(f"Could not fetch CWE details: {e}")

def test_file():
    """Test a file for CWE detection"""
    print("--- Test File ---")
    file_path = input("File path: ").strip()
    if not file_path:
        return
    
    model_path = "build/simple/cwe_model_latest.pkl"
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
        
        show_cwe_details(prediction)
        
    except Exception as e:
        print(f"Error: {e}")

def test_code():
    """Test code snippet for CWE detection"""
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
    
    if not lines:
        return
    
    model_path = "build/simple/cwe_model_latest.pkl"
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
        
        show_cwe_details(prediction)
        
    except Exception as e:
        print(f"Error: {e}")

def archive_model():
    """Archive current model"""
    print("--- Archive Model ---")
    try:
        from stats.old_stat import archive_current_stats
        archive_current_stats()
        print("✓ Model archived successfully")
    except Exception as e:
        print(f"✗ Archive failed: {e}")

def cwe_info():
    """Show CWE information"""
    print("--- CWE Information ---")
    cwe_input = input("Enter CWE ID (e.g., 79): ").strip()
    try:
        cwe_id = int(cwe_input)
        show_cwe_details(f"CWE{cwe_id}")
    except ValueError:
        print("Invalid CWE ID format")

def detect_menu():
    """Interactive detection menu"""
    model_path = "build/simple/cwe_model_latest.pkl"
    if not os.path.exists(model_path):
        print("No model found. Run setup first.")
        return
    
    print("\n=== CWE Detection Menu ===")
    
    menu_options = {
        "1": ("Test file", test_file),
        "2": ("Test code", test_code),
        "3": ("Archive", archive_model),
        "4": ("CWE Info", cwe_info),
        "5": ("Exit", None)
    }
    
    while True:
        print("\nOptions:")
        for key, (desc, _) in menu_options.items():
            print(f"{key}. {desc}")
        
        try:
            choice = input("\nChoice: ").strip()
            
            if choice in menu_options:
                desc, func = menu_options[choice]
                if func:
                    func()
                else:  # Exit
                    print("Exiting...")
                    break
            else:
                print("Invalid choice")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break

def full_setup():
    """Run the complete setup pipeline"""
    print("=== SuperDetector20000 ===")
    print("Starting full setup pipeline...")
    
    steps = [
        setup_cwe_api,
        setup_dataset,
        train_model,
        validate_model,
        generate_statistics
    ]
    
    for step in steps:
        if not step():
            if step == setup_cwe_api:
                # CWE API is optional, continue without it
                continue
            else:
                print("Pipeline failed")
                sys.exit(1)
    
    print("\n✓ Setup completed successfully!")

def update_api_data():
    """Update CWE API data only"""
    print("=== Updating CWE API Data ===")
    try:
        from src.utils.cwe_api import update_cwe_database
        update_cwe_database()
        print("✓ CWE API data updated successfully")
        
        # Ask if user wants to rebuild dataset
        choice = input("\nRebuild dataset with new API data? (y/n): ")
        if choice.lower() == 'y':
            # Force dataset recreation
            csv_path = "datasets/dataset.csv"
            if os.path.exists(csv_path):
                os.remove(csv_path)
            setup_dataset()
            print("✓ Dataset rebuilt with updated API data")
            
    except Exception as e:
        print(f"✗ API update failed: {e}")

def clean_project():
    """Clean project files"""
    print("--- Clean Project ---")
    try:
        from src.simple.detect import selective_clean
        selective_clean()
        print("✓ Project cleaned successfully")
    except ImportError:
        print("✗ Cleanup module not available")
    except Exception as e:
        print(f"✗ Cleanup failed: {e}")

def main():
    """Main application entry point"""
    print("=== SuperDetector20000 ===")
    print("Choose mode:")
    
    main_options = {
        "1": ("Full setup (API + dataset + training + validation + stats)", full_setup),
        "2": ("Test existing model only", detect_menu),
        "3": ("Update CWE API data only", update_api_data),
        "4": ("Clean project", clean_project),
        "5": ("Exit", None)
    }
    
    while True:
        print()
        for key, (desc, _) in main_options.items():
            print(f"{key}. {desc}")
        
        try:
            choice = input("\nChoice (1-5): ").strip()
            
            if choice in main_options:
                desc, func = main_options[choice]
                
                if choice == "1":  # Full setup
                    func()
                    choice = input("\nStart detection menu? (y/n): ")
                    if choice.lower() == 'y':
                        detect_menu()
                    break
                    
                elif choice == "2":  # Test model
                    model_path = "build/simple/cwe_model_latest.pkl"
                    if not os.path.exists(model_path):
                        print("✗ No trained model found. Please run full setup first.")
                        continue
                    print("✓ Model found. Starting detection menu...")
                    func()
                    break
                    
                elif choice == "3":  # Update API
                    func()
                    
                elif choice == "4":  # Clean
                    func()
                    
                elif choice == "5":  # Exit
                    print("Exiting...")
                    sys.exit(0)
                    
            else:
                print("Invalid choice. Please enter 1-5.")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)