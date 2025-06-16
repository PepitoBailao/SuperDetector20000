import os
import re
import pandas as pd
import json
from bs4 import BeautifulSoup

def clean_code(code):
    """Clean code by removing comments and normalizing whitespace"""
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//.*', '', code)
    code = re.sub(r'///.*', '', code)
    code = re.sub(r'\s+', ' ', code)
    return code.strip()

def extract_cwe_from_path(filepath):
    """Extract CWE identifier from file path"""
    dir_match = re.search(r"CWE(\d+)", os.path.dirname(filepath))
    if dir_match:
        return f"CWE{dir_match.group(1)}"
    
    file_match = re.search(r"(CWE\d+)", os.path.basename(filepath))
    return file_match.group(1) if file_match else "Unknown"

def parse_juliet_dataset(root_dir):
    """Parse Juliet Test Suite files"""
    samples = []
    
    print(f"Parsing Juliet dataset from: {root_dir}")
    
    for subdir, _, files in os.walk(root_dir):
        for filename in files:
            if not filename.endswith(('.c', '.cpp')):
                continue
                
            filepath = os.path.join(subdir, filename)
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    raw_code = f.read()
                
                cleaned_code = clean_code(raw_code)
                
                if len(cleaned_code.strip()) < 50:
                    continue
                
                cwe = extract_cwe_from_path(filepath)
                
                if cwe == "Unknown":
                    continue
                
                samples.append({
                    'cwe': cwe,
                    'code': cleaned_code,
                    'source': 'JULIET'
                })
                    
            except:
                continue
    
    print(f"Parsed {len(samples)} samples from Juliet dataset")
    return samples

def parse_csharp_dataset(root_dir):
    """Parse C# Vulnerability Test Suite files"""
    samples = []
    
    print(f"Parsing C# dataset from: {root_dir}")
    
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
                    if len(cleaned_code) > 20:
                        samples.append({
                            'cwe': cwe, 
                            'code': cleaned_code,
                            'source': 'CSHARP'
                        })                  
                except Exception:
                    continue
    
    print(f"Parsed {len(samples)} samples from C# dataset")
    return samples

def parse_web_scraped_data(scraped_data_dir):
    """Parse web scraped CWE examples"""
    samples = []
    
    if not os.path.exists(scraped_data_dir):
        print(f"Web scraped data directory not found: {scraped_data_dir}")
        return samples
    
    print(f"Parsing web scraped data from: {scraped_data_dir}")
    
    for filename in os.listdir(scraped_data_dir):
        if not filename.endswith('.html'):
            continue
            
        cwe_match = re.search(r'CWE(\d+)', filename)
        if not cwe_match:
            continue
            
        cwe = f"CWE{cwe_match.group(1)}"
        filepath = os.path.join(scraped_data_dir, filename)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            codes = extract_code_from_html(html_content)
            
            for code in codes:
                cleaned_code = clean_code(code)
                if len(cleaned_code) > 10:
                    samples.append({
                        'cwe': cwe,
                        'code': cleaned_code,
                        'source': 'WEB_SCRAPED'
                    })
                    
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
            continue
    
    print(f"Parsed {len(samples)} samples from web scraped data")
    return samples

def extract_code_from_html(html):
    """Extract code snippets from HTML content"""
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
    
    for selector in selectors:
        for element in soup.select(selector):
            text = element.get_text(separator='\n', strip=True)
            text = re.sub(r'\s+', ' ', text).replace('\r', '').replace('\xa0', ' ').strip()
            
            if (len(text) > 10 and
                any(keyword in text.lower() for keyword in keywords)):
                snippets.append(text)
    
    return snippets

def parse_api_data():
    """Parse CWE API data"""
    samples = []
    db_path = "cache/cwe_database.json"
    
    if not os.path.exists(db_path):
        print("CWE API database not found")
        return samples
    
    print("Parsing CWE API data...")
    
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            db = json.load(f)
        
        for cwe_id, cwe_data in db.get('cwes', {}).items():
            examples = cwe_data.get('code_examples', [])
            
            for i, example in enumerate(examples):
                cleaned_code = clean_code(example)
                if cleaned_code.strip():
                    samples.append({
                        'cwe': f"CWE{cwe_id}",
                        'code': cleaned_code,
                        'source': f"API_{i}"
                    })
        
        print(f"Parsed {len(samples)} samples from API data")
        
    except Exception as e:
        print(f"Error parsing API data: {e}")
    
    return samples

def create_dataset_csv(output_path="datasets/dataset.csv"):
    """Create unified dataset CSV from all parsed sources"""
    all_samples = []
    
    print("Creating unified dataset...")
    
    # Parse all data sources
    datasets_base = "datasets"
    
    # 1. Parse API data
    api_samples = parse_api_data()
    all_samples.extend(api_samples)
    
    # 2. Parse Juliet dataset
    juliet_path = os.path.join(datasets_base, "juliet", "extracted")
    if os.path.exists(juliet_path):
        juliet_samples = parse_juliet_dataset(juliet_path)
        all_samples.extend(juliet_samples)
    
    # 3. Parse C# dataset
    csharp_path = os.path.join(datasets_base, "csharp", "extracted")
    if os.path.exists(csharp_path):
        csharp_samples = parse_csharp_dataset(csharp_path)
        all_samples.extend(csharp_samples)
    
    # 4. Parse web scraped data
    web_scraped_path = os.path.join(datasets_base, "web_scraped")
    if os.path.exists(web_scraped_path):
        web_samples = parse_web_scraped_data(web_scraped_path)
        all_samples.extend(web_samples)
    
    if not all_samples:
        raise Exception("No samples found from any source")
    
    # Create DataFrame
    df = pd.DataFrame(all_samples)
    
    # Show statistics
    print(f"\nDataset statistics:")
    print(f"Total samples: {len(df)}")
    
    if 'source' in df.columns:
        source_counts = df['source'].value_counts()
        print("Source distribution:")
        for source, count in source_counts.items():
            print(f"  {source}: {count} samples")
    
    cwe_counts = df['cwe'].value_counts()
    print(f"Total CWE types: {len(cwe_counts)}")
    
    # Save to CSV
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False, encoding='utf-8')
    
    print(f"\nDataset saved to: {output_path}")
    print(f"Top 10 CWEs:")
    for cwe, count in cwe_counts.head(10).items():
        print(f"  {cwe}: {count} samples")
    
    return output_path

if __name__ == "__main__":
    create_dataset_csv()