import os
import urllib.request
import zipfile
import requests
from bs4 import BeautifulSoup
import re

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
        print(f"Downloading {zip_name}...")
        urllib.request.urlretrieve(url, zip_path)
        
        print(f"Extracting {zip_name}...")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_path)
        
        os.remove(zip_path)
        print(f"Downloaded and extracted {zip_name}")
    else:
        print(f"{extract_dir} already exists")
    
    return extract_path

def download_juliet_dataset():
    print("Downloading Juliet Test Suite...")
    return download_and_extract(JULIET_URL, "datasets/juliet", "juliet.zip", "extracted")

def download_csharp_dataset():
    print("Downloading C# Vulnerability Test Suite...")
    return download_and_extract(CSHARP_URL, "datasets/csharp", "csharp.zip", "extracted")

def scrape_cwe_pages():
    print("Scraping CWE pages from MITRE...")
    
    scraped_dir = "datasets/web_scraped"
    os.makedirs(scraped_dir, exist_ok=True)
    
    for cwe_id, url in CWE_URLS.items():
        output_file = os.path.join(scraped_dir, f"{cwe_id}.html")
        
        if os.path.exists(output_file):
            print(f"{cwe_id} already scraped")
            continue
        
        try:
            print(f"Scraping {cwe_id}...")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            print(f"{cwe_id} scraped successfully")
            
        except Exception as e:
            print(f"Failed to scrape {cwe_id}: {e}")
    
    print("CWE scraping completed")

def download_datasets():
    download_all_datasets()

def download_all_datasets():
    print("Downloading All Datasets")
    
    try:
        download_juliet_dataset()
    except Exception as e:
        print(f"Juliet download failed: {e}")
    
    try:
        download_csharp_dataset()
    except Exception as e:
        print(f"C# download failed: {e}")
    
    try:
        scrape_cwe_pages()
    except Exception as e:
        print(f"Web scraping failed: {e}")
    
    print("Dataset Download Complete")

if __name__ == "__main__":
    download_all_datasets()