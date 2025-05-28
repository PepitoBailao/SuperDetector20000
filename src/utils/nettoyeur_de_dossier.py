import os
import shutil

def clean_datasets(base_dir="datasets"):
    """Remove all subdirectories in datasets"""
    if os.path.isdir(base_dir):
        for entry in os.listdir(base_dir):
            path = os.path.join(base_dir, entry)
            if os.path.isdir(path):
                shutil.rmtree(path)
                print("deleted:", entry)

def clean_build(base_dir="build"):
    """Remove all subdirectories and files in build"""
    if os.path.isdir(base_dir):
        for entry in os.listdir(base_dir):
            path = os.path.join(base_dir, entry)
            if os.path.isdir(path):
                shutil.rmtree(path)
                print("deleted directory:", entry)
            elif os.path.isfile(path):
                os.remove(path)
                print("deleted file:", entry)

def clean_all():
    """Clean both datasets and build directories"""
    print("Cleaning datasets...")
    clean_datasets()
    print("Cleaning build...")
    clean_build()
    print("Cleanup complete!")

if __name__ == "__main__":
    clean_all()