import os
import sys

def ensure_directories():
    dirs = [
        "src/simple",
        "src/utils", 
        "build/simple",
        "cache",
        "datasets",
        "stats"
    ]
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)

def setup_cwe_api():
    print("[1/5] Setting up CWE API database...")
    while True:
        choice = input("Use CWE API? (y/n/skip): ").strip().lower()
        if choice in ['y', 'yes']:
            break
        elif choice in ['n', 'no', 'skip']:
            print("⚠ Skipping CWE API setup")
            print("  Training will use only external datasets...")
            return True
        else:
            print("Please enter 'y', 'n', or 'skip'")
    try:
        from src.utils.cwe_api import update_cwe_database
        update_cwe_database()
        print("✓ CWE API database updated successfully")
        return True
    except Exception as e:
        print(f"⚠ CWE API setup failed: {e}")
        
        # Proposer de continuer sans l'API
        while True:
            choice = input("Continue without API? (y/n): ").strip().lower()
            if choice in ['y', 'yes']:
                print("  Continuing without API data...")
                return True
            elif choice in ['n', 'no']:
                print("  Aborting setup...")
                return False
            else:
                print("Please enter 'y' or 'n'")

def download_datasets():
    """Download external datasets"""
    print("[2/5] Downloading datasets...")
    try:
        from src.utils.dataset import download_all_datasets
        download_all_datasets()
        print("✓ Datasets downloaded successfully")
        return True
    except Exception as e:
        print(f"✗ Dataset download failed: {e}")
        return False

def parse_datasets():
    """Parse all datasets into unified CSV"""
    print("[3/5] Parsing datasets...")
    try:
        from src.utils.parser import create_dataset_csv
        csv_path = create_dataset_csv()
        print(f"✓ Dataset CSV created: {csv_path}")
        return True
    except Exception as e:
        print(f"✗ Dataset parsing failed: {e}")
        return False

def train_model():
    """Train the CWE classification model"""
    print("[4/5] Training model...")
    try:
        from src.simple.train import train_model_from_csv
        model = train_model_from_csv()
        print("✓ Model trained successfully")
        return True
    except Exception as e:
        print(f"✗ Model training failed: {e}")
        return False

def validate_model():
    """Validate the trained model"""
    print("[5/5] Validating model...")
    try:
        from src.simple.detect import detect_cwe_in_code
        
        test_codes = [
            "int main() { return 0; }",
            "char buf[10]; strcpy(buf, user_input);",
            "if (password == stored_password) { authenticate(); }"
        ]
        
        for i, code in enumerate(test_codes):
            result = detect_cwe_in_code(code)
            print(f"  Test {i+1}: {result['primary_prediction']} ({result['primary_confidence']:.1%})")
        
        print("✓ Model validation successful")
        return True
    except Exception as e:
        print(f"✗ Model validation failed: {e}")
        return False

def quick_setup():
    """Quick setup without API"""
    print("=== SuperDetector20000 Quick Setup (No API) ===")
    
    steps = [
        download_datasets,
        parse_datasets,
        train_model,
        validate_model
    ]
    
    for step in steps:
        if not step():
            print("Quick setup pipeline failed")
            return False
    
    print("\n✓ Quick setup completed successfully!")
    return True

def full_setup():
    """Run the complete setup pipeline"""
    print("=== SuperDetector20000 Full Setup ===")
    
    steps = [
        setup_cwe_api,
        download_datasets,
        parse_datasets,
        train_model,
        validate_model
    ]
    
    for step in steps:
        if not step():
            print("Setup pipeline failed")
            return False
    
    print("\n✓ Full setup completed successfully!")
    return True

def test_file():
    """Test a file for CWE detection"""
    print("--- Test File ---")
    file_path = input("File path: ").strip()
    if not file_path:
        return
    
    try:
        from src.simple.detect import detect_cwe_in_file, print_detection_results
        result = detect_cwe_in_file(file_path)
        print_detection_results(result)
        
        # Show CWE details
        show_cwe_details(result['primary_prediction'])
        
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
    
    try:
        from src.simple.detect import detect_cwe_in_code, print_detection_results
        result = detect_cwe_in_code("\n".join(lines))
        print_detection_results(result)
        
        # Show CWE details
        show_cwe_details(result['primary_prediction'])
        
    except Exception as e:
        print(f"Error: {e}")

def show_cwe_details(cwe_name):
    """Show detailed CWE information"""
    try:
        if cwe_name == "Unknown" or not cwe_name.startswith('CWE'):
            print(f"\n--- {cwe_name} Details ---")
            print("No CWE details available for this prediction")
            return
            
        from src.utils.cwe_api import get_cwe_info
        cwe_id = int(cwe_name.replace('CWE', ''))
        cwe_info = get_cwe_info(cwe_id)
        
        print(f"\n--- {cwe_name} Details ---")
        print(f"Name: {cwe_info.get('name', 'Unknown')}")
        
        description = cwe_info.get('description', 'No description available')
        if len(description) > 200:
            description = description[:200] + "..."
        print(f"Description: {description}")
        
    except Exception as e:
        print(f"Could not fetch CWE details: {e}")

def clean_project():
    print("--- Clean Project ---")
    try:
        from src.utils.nettoyeur_de_dossier import clean_all
        clean_all()
        print("✓ Project cleaned successfully")
    except Exception as e:
        print(f"✗ Cleanup failed: {e}")

def detection_menu():
    """Detection menu"""
    model_path = "build/simple/cwe_model_latest.pkl"
    if not os.path.exists(model_path):
        print("No model found. Run setup first.")
        return
    
    print("\n=== CWE Detection Menu ===")
    
    while True:
        print("\nOptions:")
        print("1. Test file")
        print("2. Test code snippet")
        print("3. Exit")
        
        try:
            choice = input("\nChoice: ").strip()
            
            if choice == "1":
                test_file()
            elif choice == "2":
                test_code()
            elif choice == "3":
                break
            else:
                print("Invalid choice")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break

def main():
    """Main application entry point"""
    print("=== SuperDetector20000 ===")

    ensure_directories()
    
    while True:
        print("\nChoose mode:")
        print("1. Full setup (API + datasets + training)")
        print("2. Quick setup (datasets only + training)")
        print("3. Test existing model")
        print("4. Clean project")
        print("5. Exit")
        
        try:
            choice = input("\nChoice (1-5): ").strip()
            
            if choice == "1":
                if full_setup():
                    answer = input("\nStart detection menu? (y/n): ")
                    if answer.lower() == 'y':
                        detection_menu()
                break
                
            elif choice == "2":
                if quick_setup():
                    answer = input("\nStart detection menu? (y/n): ")
                    if answer.lower() == 'y':
                        detection_menu()
                break
                
            elif choice == "3":
                detection_menu()
                break
                
            elif choice == "4":
                clean_project()
                
            elif choice == "5":
                print("Exiting...")
                break
                
            else:
                print("Invalid choice. Please enter 1-5.")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)