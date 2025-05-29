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
    print_step(1, 5, "Setup dataset")
    
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