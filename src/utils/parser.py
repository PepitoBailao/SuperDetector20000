import os
import re
import pandas as pd
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.cleaner import nettoyer_code

def extract_cwe_from_filename(fn):
    m = re.search(r"(CWE\d+)", fn)
    return m.group(1) if m else "Unknown"

def extract_cwe_from_path(filepath):
    dir_match = re.search(r"CWE(\d+)", os.path.dirname(filepath))
    return f"CWE{dir_match.group(1)}" if dir_match else extract_cwe_from_filename(os.path.basename(filepath))

def determine_sample_type(filename):
    filename_lower = filename.lower()
    if 'bad' in filename_lower or 'vuln' in filename_lower:
        return 'bad'
    elif 'good' in filename_lower or 'fix' in filename_lower:
        return 'good'
    else:
        return 'mixed'

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
                
                cleaned_code = nettoyer_code(raw_code)
                
                if len(cleaned_code.strip()) < 50:
                    continue
                
                cwe = extract_cwe_from_path(filepath)
                
                # Skip files without valid CWE
                if cwe == "Unknown":
                    continue
                
                samples.append({
                    'filename': filename,
                    'filepath': filepath,
                    'cwe': cwe,
                    'sample_type': determine_sample_type(filename),
                    'code': cleaned_code,
                    'raw_code_length': len(raw_code),
                    'cleaned_code_length': len(cleaned_code)
                })
                    
            except Exception:
                continue
    
    # Create DataFrame without problematic dtypes
    df = pd.DataFrame(samples)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False, encoding='utf-8')
    print(f"Parsed {len(df)} samples with {df['cwe'].nunique()} unique CWEs")
    return output_csv

if __name__ == "__main__":
    ROOT = "datasets/juliet/extracted/C/testcases"
    if os.path.exists(ROOT):
        parse_juliet_to_csv(ROOT)
        print("Parsing complete!")