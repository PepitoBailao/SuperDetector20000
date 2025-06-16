import os
import shutil

def clean_datasets(base_dir="datasets"):
    """Clean datasets directory"""
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
    """Clean build directory"""
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

def clean_cache(base_dir="cache"):
    """Clean cache directory"""
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

def clean_all():
    """Clean all generated directories"""
    print("=== Cleaning SuperDetector20000 ===")
    clean_datasets()
    clean_build()
    clean_cache()
    print("=== Cleanup completed ===")

if __name__ == "__main__":
    clean_all()