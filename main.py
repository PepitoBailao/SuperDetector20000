import os
import sys

# Add project root and module paths to sys.path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))
sys.path.insert(0, os.path.join(project_root, 'src', 'simple'))
sys.path.insert(0, os.path.join(project_root, 'src', 'utils'))

def ensure_directories():
    dirs = ["datasets", "build/simple", "cache", "src/simple", "src/utils"]
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)

def safe_import(module_name, module_path=None):
    """Safely import a module with fallback paths"""
    if module_path:
        old_path = sys.path.copy()
        sys.path.insert(0, module_path)
    
    try:
        return __import__(module_name)
    except ImportError as e:
        print(f"Failed to import {module_name}: {e}")
        return None
    finally:
        if module_path:
            sys.path = old_path

def setup_cwe_api():
    print("[1/5] Setting up CWE API...")
    choice = input("Use CWE API? (y/n): ").strip().lower()
    if choice in ['n', 'no']:
        print("Skipping CWE API")
        return True
    
    cwe_api = None
    
    try:
        import CWE_api as cwe_api
    except ImportError:
        try:
            cwe_api = safe_import('CWE_api', 'src/utils')
        except:
            pass
    
    if cwe_api is None:
        print("CWE API module not found, skipping")
        return True
    
    try:
        if hasattr(cwe_api, 'update_cwe_database'):
            cwe_api.update_cwe_database(fast_mode=True)
        elif hasattr(cwe_api, 'fetch_cwe_data'):
            cwe_api.fetch_cwe_data()
        else:
            print("CWE API function not found")
            return True
        
        print("CWE API complete")
        return True
    except Exception as e:
        print(f"CWE API failed: {e}")
        return True

def download_datasets():
    print("[2/5] Downloading datasets...")
    
    dataset = None
    
    try:
        import dataset
    except ImportError:
        try:
            dataset = safe_import('dataset', 'src/utils')
        except:
            pass
    
    if dataset is None:
        print("Dataset module not found")
        return False
    
    try:
        if hasattr(dataset, 'download_all_datasets'):
            dataset.download_all_datasets()
        elif hasattr(dataset, 'download_datasets'):
            dataset.download_datasets()
        else:
            print("Download function not found")
            return False
        
        print("Download complete")
        return True
    except Exception as e:
        print(f"Download failed: {e}")
        return False

def parse_datasets():
    print("[3/5] Parsing datasets...")
    
    parser = None
    
    try:
        import parser
    except ImportError:
        try:
            parser = safe_import('parser', 'src/utils')
        except:
            pass
    
    if parser is None:
        print("Parser module not found")
        return False
    
    try:
        if hasattr(parser, 'extract_files'):
            parser.extract_files()
        if hasattr(parser, 'process_datasets'):
            parser.process_datasets()
        elif hasattr(parser, 'create_dataset_csv'):
            parser.create_dataset_csv()
        else:
            print("Parser functions not found")
            return False
        
        print("Parsing complete")
        return True
    except Exception as e:
        print(f"Parsing failed: {e}")
        return False

def train_model():
    print("[4/5] Training model...")
    
    train = None
    
    try:
        import train
    except ImportError:
        try:
            train = safe_import('train', 'src/simple')
        except:
            pass
    
    if train is None:
        print("Train module not found")
        return False
    
    try:
        if hasattr(train, 'train_model_from_csv'):
            train.train_model_from_csv()
        elif hasattr(train, 'train_model'):
            train.train_model()
        else:
            print("Train function not found")
            return False
        
        print("Training complete")
        return True
    except Exception as e:
        print(f"Training failed: {e}")
        return False

def validate_model():
    print("[5/5] Validating model...")
    
    detect = None
    
    try:
        import detect
    except ImportError:
        try:
            detect = safe_import('detect', 'src/simple')
        except:
            pass
    
    if detect is None:
        print("Detect module not found")
        return False
    
    try:
        test_code = "char buf[10]; strcpy(buf, input);"
        
        if hasattr(detect, 'detect_cwe_in_code'):
            result = detect.detect_cwe_in_code(test_code)
            if isinstance(result, dict):
                print(f"Test result: {result.get('primary_prediction', 'Unknown')}")
            else:
                print(f"Test result: {result}")
        elif hasattr(detect, 'analyze_code'):
            result = detect.analyze_code(test_code)
            print(f"Test result: {result}")
        else:
            print("Detect function not found")
            return False
        
        print("Validation complete")
        return True
    except Exception as e:
        print(f"Validation failed: {e}")
        return False

def quick_setup():
    print("=== Quick Setup ===")
    steps = [download_datasets, parse_datasets, train_model, validate_model]
    for step in steps:
        if not step():
            return False
    print("Setup complete")
    return True

def full_setup():
    print("=== Full Setup ===")
    steps = [setup_cwe_api, download_datasets, parse_datasets, train_model, validate_model]
    for step in steps:
        if not step():
            return False
    print("Setup complete")
    return True

def test_file():
    file_path = input("File path: ").strip()
    if not os.path.exists(file_path):
        print("File not found")
        return
    
    detect = None
    
    try:
        import detect
    except ImportError:
        try:
            detect = safe_import('detect', 'src/simple')
        except:
            pass
    
    if detect is None:
        print("Detect module not found")
        return
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        if hasattr(detect, 'detect_cwe_in_file'):
            result = detect.detect_cwe_in_file(file_path)
        elif hasattr(detect, 'detect_cwe_in_code'):
            result = detect.detect_cwe_in_code(code)
        elif hasattr(detect, 'analyze_code'):
            result = detect.analyze_code(code)
        else:
            print("No detection function found")
            return
        
        if isinstance(result, dict):
            prediction = result.get('primary_prediction', 'Unknown')
            confidence = result.get('primary_confidence', 0)
            print(f"Result: {prediction} ({confidence:.1%})")
        else:
            print(f"Result: {result}")
            
    except Exception as e:
        print(f"Error: {e}")

def test_code():
    print("Enter code (type END to finish):")
    lines = []
    while True:
        try:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        except:
            break
    
    if not lines:
        return
    
    detect = None
    
    try:
        import detect
    except ImportError:
        try:
            detect = safe_import('detect', 'src/simple')
        except:
            pass
    
    if detect is None:
        print("Detect module not found")
        return
    
    try:
        code = "\n".join(lines)
        
        if hasattr(detect, 'detect_cwe_in_code'):
            result = detect.detect_cwe_in_code(code)
        elif hasattr(detect, 'analyze_code'):
            result = detect.analyze_code(code)
        else:
            print("No detection function found")
            return
        
        if isinstance(result, dict):
            prediction = result.get('primary_prediction', 'Unknown')
            confidence = result.get('primary_confidence', 0)
            print(f"Result: {prediction} ({confidence:.1%})")
        else:
            print(f"Result: {result}")
            
    except Exception as e:
        print(f"Error: {e}")

def clean_project():
    nettoyeur = None
    
    # Try different import methods for nettoyeur_de_dossier
    try:
        import nettoyeur_de_dossier
        nettoyeur = nettoyeur_de_dossier
    except ImportError:
        try:
            nettoyeur = safe_import('nettoyeur_de_dossier', 'src/utils')
        except:
            pass
    
    if nettoyeur is None:
        print("Cleaner module not found")
        # Fallback manual cleanup
        try:
            import shutil
            dirs_to_clean = ["datasets", "build", "cache"]
            for dir_name in dirs_to_clean:
                if os.path.exists(dir_name):
                    shutil.rmtree(dir_name)
                    print(f"Removed {dir_name}")
            files_to_clean = ["dataset.csv", "cwe_model.pkl", "vectorizer.pkl"]
            for file_name in files_to_clean:
                if os.path.exists(file_name):
                    os.remove(file_name)
                    print(f"Removed {file_name}")
            print("Manual cleanup completed")
        except Exception as e:
            print(f"Manual cleanup failed: {e}")
        return
    
    try:
        if hasattr(nettoyeur, 'clean_all'):
            nettoyeur.clean_all()
        elif hasattr(nettoyeur, 'clean_folder'):
            nettoyeur.clean_folder()
        else:
            print("Clean function not found")
            return
        
        print("Cleaned")
    except Exception as e:
        print(f"Clean failed: {e}")

def detection_menu():
    model_paths = [
        "build/simple/cwe_model_latest.pkl",
        "cwe_model.pkl",
        "src/simple/cwe_model.pkl"
    ]
    
    model_exists = any(os.path.exists(path) for path in model_paths)
    
    if not model_exists:
        print("No model found")
        return
    
    while True:
        print("\n1. Test file")
        print("2. Test code")
        print("3. Exit")
        choice = input("Choice: ").strip()
        if choice == "1":
            test_file()
        elif choice == "2":
            test_code()
        elif choice == "3":
            break

def main():
    print("=== SuperDetector20000 ===")
    ensure_directories()
    
    while True:
        print("\n1. Full setup")
        print("2. Quick setup")
        print("3. Test model")
        print("4. Clean")
        print("5. Exit")
        
        choice = input("Choice: ").strip()
        
        if choice == "1":
            if full_setup():
                detection_menu()
            break
        elif choice == "2":
            if quick_setup():
                detection_menu()
            break
        elif choice == "3":
            detection_menu()
        elif choice == "4":
            clean_project()
        elif choice == "5":
            break

if __name__ == "__main__":
    main()