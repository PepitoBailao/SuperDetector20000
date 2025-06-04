import os
import shutil

def clean_datasets(base_dir="datasets"):
    """Clean all datasets directory contents"""
    if os.path.isdir(base_dir):
        print(f"Cleaning {base_dir}...")
        for entry in os.listdir(base_dir):
            path = os.path.join(base_dir, entry)
            if os.path.isdir(path):
                shutil.rmtree(path)
                print(f"  Removed directory: {entry}")
            elif os.path.isfile(path):
                os.remove(path)
                print(f"  Removed file: {entry}")
        print(f"✓ {base_dir} cleaned")
    else:
        print(f"Directory {base_dir} does not exist")

def clean_build(base_dir="build"):
    """Clean all build directory contents"""
    if os.path.isdir(base_dir):
        print(f"Cleaning {base_dir}...")
        for entry in os.listdir(base_dir):
            path = os.path.join(base_dir, entry)
            if os.path.isdir(path):
                shutil.rmtree(path)
                print(f"  Removed directory: {entry}")
            elif os.path.isfile(path):
                os.remove(path)
                print(f"  Removed file: {entry}")
        print(f"✓ {base_dir} cleaned")
    else:
        print(f"Directory {base_dir} does not exist")

def clean_stats(base_dir="stats"):
    """Clean generated statistics files but keep templates"""
    if os.path.isdir(base_dir):
        print(f"Cleaning {base_dir}...")
        files_to_remove = [
            "model_statistics.json",
            "archived_stats"
        ]
        for entry in files_to_remove:
            path = os.path.join(base_dir, entry)
            if os.path.isfile(path):
                os.remove(path)
                print(f"  Removed file: {entry}")
            elif os.path.isdir(path):
                shutil.rmtree(path)
                print(f"  Removed directory: {entry}")
        print(f"✓ {base_dir} cleaned")

def clean_all():
    """Clean all generated files and directories"""
    print("=== Cleaning SuperDetector20000 ===")
    clean_datasets()
    clean_build()
    clean_stats()
    print("=== Cleanup completed ===")

def selective_clean():
    """Interactive cleanup menu"""
    print("\n=== SuperDetector20000 Cleanup Menu ===")
    print("1. Clean datasets only")
    print("2. Clean build only")
    print("3. Clean stats only")
    print("4. Clean all")
    print("5. Exit")
    
    choice = input("\nChoice (1-5): ").strip()
    
    if choice == "1":
        clean_datasets()
    elif choice == "2":
        clean_build()
    elif choice == "3":
        clean_stats()
    elif choice == "4":
        clean_all()
    elif choice == "5":
        print("Cleanup cancelled")
    else:
        print("Invalid choice")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        selective_clean()
    else:
        clean_all()