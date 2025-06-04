import os
import urllib.request
import zipfile
import requests
from bs4 import BeautifulSoup
import re
import pandas as pd

JULIET_URL = (
    "https://samate.nist.gov/SARD/downloads/"
    "test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
)

CSHARP_URL = (
    "https://samate.nist.gov/SARD/downloads/"
    "test-suites/2016-09-12-csharp-vulnerability-test-suite.zip"
)

CWE_URLS = {
    "CWE20": "https://cwe.mitre.org/data/definitions/20.html",
    "CWE22": "https://cwe.mitre.org/data/definitions/22.html",
    "CWE19": "https://cwe.mitre.org/data/definitions/19.html",
    "CWE94": "https://cwe.mitre.org/data/definitions/94.html",
    "CWE798": "https://cwe.mitre.org/data/definitions/798.html"
}

def download_and_extract(url, base_dir, zip_name, extract_dir):
    os.makedirs(base_dir, exist_ok=True)
    zip_path = os.path.join(base_dir, zip_name)
    extract_path = os.path.join(base_dir, extract_dir)
    
    if not os.path.exists(extract_path):
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_path)
        os.remove(zip_path)
    
    return extract_path

def download_juliet_dataset():
    return download_and_extract(JULIET_URL, "datasets/juliet", "juliet.zip", "extracted")

def download_csharp_dataset():
    return download_and_extract(CSHARP_URL, "datasets/csharp", "csharp.zip", "extracted")

def clean_code(code):
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//.*', '', code)
    code = re.sub(r'///.*', '', code)
    code = re.sub(r'\s+', ' ', code)
    return code.strip()

def extract_code_from_div_top(html):
    soup = BeautifulSoup(html, "html.parser")
    snippets = []
    selectors = ['div.Example_Code', 'div.code', 'pre.code', 'code', 'pre', 'div.top']
    
    for selector in selectors:
        for element in soup.select(selector):
            text = element.get_text(separator='\n', strip=True)
            if len(text) > 30 and any(keyword in text.lower() for keyword in ['int ', 'char ', 'void ', 'class ', 'public ']):
                snippets.append(text.replace('\r', '').replace('\xa0', ' ').strip())
    
    return snippets

def extract_cwe_from_path(filepath):
    dir_match = re.search(r"CWE(\d+)", os.path.dirname(filepath))
    if dir_match:
        return f"CWE{dir_match.group(1)}"
    
    file_match = re.search(r"(CWE\d+)", os.path.basename(filepath))
    return file_match.group(1) if file_match else "Unknown"

def parse_juliet_to_records(root_dir):
    records = []
    
    for subdir, _, files in os.walk(root_dir):
        for filename in files:
            if not filename.endswith(('.c', '.cpp')):
                continue
                
            filepath = os.path.join(subdir, filename)
            cwe = extract_cwe_from_path(filepath)
            
            if cwe == "Unknown":
                continue
                
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    raw_code = f.read()
                
                cleaned_code = clean_code(raw_code)
                
                if len(cleaned_code) > 50:
                    records.append({"cwe": cwe, "code": cleaned_code})
                    
            except Exception:
                continue
    
    return records

def parse_csharp_to_records(root_dir):
    records = []
    
    for subdir, dirs, files in os.walk(root_dir):
        current_dir = os.path.basename(subdir)
        
        if current_dir == 'src' and re.match(r'\d+-v\d+\.\d+\.\d+', os.path.basename(os.path.dirname(subdir))):
            for filename in files:
                if not filename.endswith('.cs'):
                    continue
                
                cwe_match = re.search(r'cwe_(\d+)', filename.lower())
                if cwe_match:
                    cwe = f"CWE{cwe_match.group(1)}"
                else:
                    continue
                
                filepath = os.path.join(subdir, filename)
                
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        raw_code = f.read()
                    
                    cleaned_code = clean_code(raw_code)
                    
                    if len(cleaned_code) > 50:
                        records.append({"cwe": cwe, "code": cleaned_code})
                        
                except Exception:
                    continue
    
    return records

def scrape_cwe_examples(cwe_urls):
    records = []
    
    for cwe_id, url in cwe_urls.items():
        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            codes = extract_code_from_div_top(r.text)
            
            for code in codes:
                cleaned_code = clean_code(code)
                if len(cleaned_code) > 50:
                    records.append({"cwe": cwe_id, "code": cleaned_code})
                    
        except Exception:
            continue
    
    return records

def create_clean_dataset(output_csv="datasets/dataset.csv"):
    all_records = []
    
    try:
        juliet_dir = download_juliet_dataset()
        juliet_records = parse_juliet_to_records(juliet_dir)
        all_records.extend(juliet_records)
    except Exception:
        pass
    
    try:
        csharp_dir = download_csharp_dataset()
        csharp_records = parse_csharp_to_records(csharp_dir)
        all_records.extend(csharp_records)
    except Exception:
        pass
    
    try:
        scraped_records = scrape_cwe_examples(CWE_URLS)
        all_records.extend(scraped_records)
    except Exception:
        pass
    
    if not all_records:
        raise Exception("No records collected")
    
    df = pd.DataFrame(all_records)
    df = df.drop_duplicates(subset=['code'])
    
    cwe_counts = df['cwe'].value_counts()
    valid_cwes = cwe_counts[cwe_counts >= 3].index
    df = df[df['cwe'].isin(valid_cwes)]
    
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False, encoding='utf-8')
    
    return output_csv

if __name__ == "__main__":
    create_clean_dataset()