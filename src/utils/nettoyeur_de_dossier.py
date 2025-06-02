import os
import shutil

def clean_datasets(base_dir="datasets"):
    if os.path.isdir(base_dir):
        for entry in os.listdir(base_dir):
            path = os.path.join(base_dir, entry)
            if os.path.isdir(path):
                shutil.rmtree(path)
            elif os.path.isfile(path):
                os.remove(path)

"""def clean_build(base_dir="build"):
    if os.path.isdir(base_dir):
        for entry in os.listdir(base_dir):
            path = os.path.join(base_dir, entry)
            if os.path.isdir(path):
                shutil.rmtree(path)
            elif os.path.isfile(path):
                os.remove(path)"""

def clean_all():
    clean_datasets()
    "clean_build()"

if __name__ == "__main__":
    clean_all()