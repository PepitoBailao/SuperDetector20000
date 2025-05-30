import os
import re
import pandas as pd
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.simple.train import clean_code

def extract_cwe_from_path(filepath):
    dir_match = re.search(r"CWE(\d+)", os.path.dirname(filepath))
    if dir_match:
        return f"CWE{dir_match.group(1)}"
    
    file_match = re.search(r"(CWE\d+)", os.path.basename(filepath))
    return file_match.group(1) if file_match else "Unknown"

def parse_juliet_to_csv(root_dir, output_csv="datasets/juliet_cwe_dataset.csv"):
    samples = []
    
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
                    'filename': filename,
                    'filepath': filepath,
                    'cwe': cwe,
                    'code': cleaned_code
                })
                    
            except Exception:
                continue
    
    df = pd.DataFrame(samples)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False, encoding='utf-8')
    print(f"Parsed {len(df)} samples with {df['cwe'].nunique()} unique CWEs")
    return output_csv