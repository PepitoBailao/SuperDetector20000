import os
import re
import csv
import pandas as pd
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.cleaner import nettoyer_code

def extract_cwe_from_filename(fn: str) -> str:
    """Extract CWE from filename"""
    m = re.search(r"(CWE\d+)", fn)
    return m.group(1) if m else "Unknown"

def extract_cwe_from_path(filepath: str) -> str:
    """Extract CWE from full file path"""
    # Try directory structure first
    dir_match = re.search(r"CWE(\d+)", os.path.dirname(filepath))
    if dir_match:
        return f"CWE{dir_match.group(1)}"
    
    # Then filename
    return extract_cwe_from_filename(os.path.basename(filepath))

def determine_sample_type(filename: str) -> str:
    """Determine if sample is good/bad/mixed"""
    filename_lower = filename.lower()
    if 'bad' in filename_lower or 'vuln' in filename_lower:
        return 'bad'
    elif 'good' in filename_lower or 'fix' in filename_lower:
        return 'good'
    else:
        return 'mixed'

def parse_juliet_to_csv(root_dir: str, output_csv: str = "datasets/juliet_cwe_dataset.csv"):
    """Parse entire Juliet dataset into single CSV file"""
    print(f"Parsing Juliet dataset from {root_dir}...")
    
    samples = []
    total_files = 0
    
    for subdir, _, files in os.walk(root_dir):
        for filename in files:
            if not filename.endswith(('.c', '.cpp')):
                continue
                
            filepath = os.path.join(subdir, filename)
            total_files += 1
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    raw_code = f.read()
                
                # Extract metadata
                cwe = extract_cwe_from_path(filepath)
                sample_type = determine_sample_type(filename)
                
                # Clean code
                cleaned_code = nettoyer_code(raw_code)
                
                # Skip if code is too short after cleaning
                if len(cleaned_code.strip()) < 50:
                    continue
                
                samples.append({
                    'filename': filename,
                    'filepath': filepath,
                    'cwe': cwe,
                    'sample_type': sample_type,
                    'code': cleaned_code,
                    'raw_code_length': len(raw_code),
                    'cleaned_code_length': len(cleaned_code)
                })
                
                if len(samples) % 1000 == 0:
                    print(f"Processed {len(samples)} samples...")
                    
            except Exception as e:
                print(f"Error processing {filepath}: {e}")
                continue
    
    # Create DataFrame and save
    df = pd.DataFrame(samples)
    
    # Create output directory
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    # Save to CSV
    df.to_csv(output_csv, index=False, encoding='utf-8')
    
    print(f"\nDataset parsing complete!")
    print(f"Total files processed: {total_files}")
    print(f"Valid samples: {len(samples)}")
    print(f"Unique CWEs: {df['cwe'].nunique()}")
    print(f"Sample type distribution:")
    print(df['sample_type'].value_counts())
    print(f"Dataset saved to: {output_csv}")
    
    return output_csv

if __name__ == "__main__":
    ROOT = "datasets/juliet/extracted/C/testcases"
    if os.path.exists(ROOT):
        parse_juliet_to_csv(ROOT)
    else:
        print(f"Dataset not found at {ROOT}. Run utils/dataset.py first.")