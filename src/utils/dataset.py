import os
import urllib.request
import zipfile

JULIET_URL = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"

def download_and_extract(url=JULIET_URL, name="juliet", base_dir="datasets"):
    path = os.path.join(base_dir, name)
    os.makedirs(path, exist_ok=True)
    zip_path = os.path.join(path, f"{name}.zip")

    print(f"Downloading {name}...")
    urllib.request.urlretrieve(url, zip_path)

    with zipfile.ZipFile(zip_path) as zf:
        print(f"Extracting {name}...")
        zf.extractall(os.path.join(path, "extracted"))

    os.remove(zip_path)
    print(f"Done: {name}")
    return os.path.join(path, "extracted")

def check_dataset_exists(base_dir="datasets"):
    return os.path.exists(os.path.join(base_dir, "juliet", "extracted", "C", "testcases"))

if __name__ == "__main__":
    if check_dataset_exists():
        print("Dataset already exists.")
    else:
        extracted_path = download_and_extract()
        print(f"Dataset ready: {extracted_path}")