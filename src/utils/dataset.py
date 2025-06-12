import os
import urllib.request
import zipfile
import requests
from bs4 import BeautifulSoup
import re
import pandas as pd
import json

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
    """Extract code snippets from HTML - improved version"""
    soup = BeautifulSoup(html, "html.parser")
    snippets = []
    
    selectors = [
        'div.Example_Code', 'div.code', 'pre.code', 'code', 'pre', 'div.top',
        'div[style*="margin-left"]', 'div.programlisting', 'div.codebox', 'span.code'
    ]
    
    keywords = [
        'int ', 'char ', 'void ', 'class ', 'public ', 'private ', 'protected ',
        'static ', 'final ', 'abstract ', 'extends ', 'implements ', 'import ',
        'package ', 'try ', 'catch ', 'throw ', 'throws ', 'if ', 'else ',
        'for ', 'while ', 'do ', 'switch ', 'case ', 'break ', 'continue ',
        'return ', 'new ', 'this ', 'super ', 'null ', 'true ', 'false ',
        '#include', 'printf', 'scanf', 'malloc', 'free', 'strcpy', 'strlen',
        'def ', 'from ', 'function', 'var ', 'let ', 'const ', 'console.log'
    ]
    
    # Keep ALL snippets, even duplicates
    for selector in selectors:
        for element in soup.select(selector):
            text = element.get_text(separator='\n', strip=True)
            text = re.sub(r'\s+', ' ', text).replace('\r', '').replace('\xa0', ' ').strip()
            
            if (len(text) > 10 and  # Lower threshold
                any(keyword in text.lower() for keyword in keywords)):
                snippets.append(text)
    
    # Find code in nested divs with margin-left styling
    for div in soup.find_all('div'):
        nested = div.find_all('div', style=lambda x: x and 'margin-left' in x)
        if nested:
            lines = []
            for nest in nested:
                text = nest.get_text(strip=True)
                if text:
                    style = nest.get('style', '')
                    margin = re.search(r'margin-left:(\d+)', style)
                    indent = int(margin.group(1)) // 20 if margin else 0
                    lines.append('    ' * indent + text)
            
            if lines:
                code = '\n'.join(lines)
                code = re.sub(r'\s+', ' ', code).replace('\r', '').replace('\xa0', ' ').strip()
                
                if (len(code) > 10 and 
                    any(keyword in code.lower() for keyword in keywords)):
                    snippets.append(code)
    
    # Find remaining code in paragraphs
    text = soup.get_text(separator='\n', strip=True)
    for para in text.split('\n\n'):
        para = para.strip()
        if (len(para) > 10 and 
            para.count('{') > 0 and para.count('}') > 0 and
            any(keyword in para.lower() for keyword in keywords)):
            para = re.sub(r'\s+', ' ', para).replace('\r', '').replace('\xa0', ' ').strip()
            snippets.append(para)
    
    return snippets  # Return ALL snippets, including duplicates

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
                if len(cleaned_code) > 20:  # Lower threshold
                    records.append({
                        "cwe": cwe, 
                        "code": cleaned_code,
                        "source": "JULIET"
                    })
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
                    if len(cleaned_code) > 20:  # Lower threshold
                        records.append({
                            "cwe": cwe, 
                            "code": cleaned_code,
                            "source": "CSHARP"
                        })                  
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
                if len(cleaned_code) > 10:  # Lower threshold
                    records.append({
                        "cwe": cwe_id, 
                        "code": cleaned_code,
                        "source": "MITRE_WEB"
                    })            
        except Exception:
            continue
    return records

def extract_api_examples():
    """Extract ALL code examples from CWE API data without filtering"""
    records = []
    db_path = "cache/cwe_database.json"
    
    if not os.path.exists(db_path):
        print("  No CWE API database found, trying to create one...")
        try:
            from src.utils.cwe_api import update_cwe_database
            update_cwe_database()
        except Exception as e:
            print(f"  Failed to create API database: {e}")
            return records
    
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            db = json.load(f)
        
        api_count = 0
        for cwe_id, cwe_data in db.get('cwes', {}).items():
            examples = cwe_data.get('code_examples', [])
            
            # Add ALL examples without length filtering or deduplication
            for i, example in enumerate(examples):
                cleaned_code = clean_code(example)
                if cleaned_code.strip():  # Only check if not empty
                    records.append({
                        "cwe": f"CWE{cwe_id}",
                        "code": cleaned_code,
                        "source": f"MITRE_API_{i}"  # Unique source to prevent removal
                    })
                    api_count += 1
        
        if api_count > 0:
            print(f"  Extracted {api_count} examples from API database (ALL examples kept)")
            
    except Exception as e:
        print(f"Error extracting API examples: {e}")
    
    return records

def create_clean_dataset(output_csv="datasets/dataset.csv"):
    all_records = []
    
    print("Creating COMPREHENSIVE dataset from multiple sources...")
    
    # 1. CWE API integration (highest priority)
    try:
        print("1. Integrating CWE API data...")
        api_records = extract_api_examples()
        all_records.extend(api_records)
        print(f"   API: {len(api_records)} records")
    except Exception as e:
        print(f"   API integration failed: {e}")
    
    # 2. Web scraping from MITRE
    try:
        print("2. Scraping MITRE CWE pages...")
        scraped_records = scrape_cwe_examples(CWE_URLS)
        all_records.extend(scraped_records)
        print(f"   Scraped: {len(scraped_records)} records")
    except Exception as e:
        print(f"   Scraping failed: {e}")
    
    # 3. Juliet dataset
    try:
        print("3. Processing Juliet Test Suite...")
        juliet_records = parse_juliet_to_records(download_juliet_dataset())
        all_records.extend(juliet_records)
        print(f"   Juliet: {len(juliet_records)} records")
    except Exception as e:
        print(f"   Juliet failed: {e}")
    
    # 4. C# dataset
    try:
        print("4. Processing C# Vulnerability Test Suite...")
        csharp_records = parse_csharp_to_records(download_csharp_dataset())
        all_records.extend(csharp_records)
        print(f"   C#: {len(csharp_records)} records")
    except Exception as e:
        print(f"   C# failed: {e}")
    
    if not all_records:
        raise Exception("No records collected from any source")
    
    print(f"\nProcessing {len(all_records)} total records...")
    
    # Process and save dataset
    df = pd.DataFrame(all_records)
    
    # Show source distribution
    if 'source' in df.columns:
        source_counts = df['source'].value_counts()
        print("Source distribution:")
        for source, count in source_counts.items():
            print(f"  {source}: {count} records")
    
    # REMOVE DUPLICATE REMOVAL - Keep ALL records
    initial_count = len(df)
    print(f"Keeping ALL {initial_count} records (no duplicate removal)")
    
    # REMOVE CWE FREQUENCY FILTERING - Keep ALL CWEs
    cwe_counts = df['cwe'].value_counts()
    print(f"Keeping ALL {len(cwe_counts)} CWE types")
    
    # Save dataset
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False, encoding='utf-8')
    
    print(f"COMPREHENSIVE dataset: {len(df)} records, {len(cwe_counts)} CWE types")
    print(f"  Saved to: {output_csv}")
    
    # Show top CWEs
    print("\nTop 15 CWEs in dataset:")
    top_cwes = cwe_counts.head(15)
    for cwe, count in top_cwes.items():
        print(f"  {cwe}: {count} samples")
    
    return output_csv

if __name__ == "__main__":
    create_clean_dataset()