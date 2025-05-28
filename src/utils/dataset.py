import os
import urllib.request
import zipfile

JULIET_URL = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"

def download_and_extract(url=JULIET_URL, name="juliet", base_dir="datasets"):
    path = os.path.join(base_dir, name)
    os.makedirs(path, exist_ok=True)
    zip_path = os.path.join(path, f"{name}.zip")

    print("[INFO] Téléchargement de Juliet...")
    urllib.request.urlretrieve(url, zip_path)

    with zipfile.ZipFile(zip_path) as zf:
        print("[INFO] Extraction de Juliet...")
        zf.extractall(os.path.join(path, "extracted"))

    os.remove(zip_path)
    print("[INFO] Extraction terminée.")
    return os.path.join(path, "extracted")


def extract_cwe_from_path(file_path):
    import re
    match = re.search(r'CWE(\d+)', file_path)
    return f"CWE{match.group(1)}" if match else None


def collect_code_samples(dataset_root, only_bad=True):
    data = []
    for root, _, files in os.walk(dataset_root):
        for file in files:
            if file.endswith(('.c', '.cpp')):
                if only_bad and '_bad' not in file:
                    continue
                full_path = os.path.join(root, file)
                cwe = extract_cwe_from_path(full_path)
                if cwe:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                    data.append((code, cwe))
    print(f"[INFO] {len(data)} fichiers chargés depuis {dataset_root}")
    return data
