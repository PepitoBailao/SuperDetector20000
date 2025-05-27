import os
import json
import re

def extract_cwe_from_filename(filename):
    match = re.search(r"(CWE\d+)", filename)
    return match.group(1) if match else "Unknown"

def parse_source_files(root_dir, file_ext=".c"):
    data = []
    for subdir, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(file_ext):
                full_path = os.path.join(subdir, file)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        code = f.read()
                    label = extract_cwe_from_filename(file)
                    is_flawed = 'bad' in file.lower()
                    data.append({
                        "filename": file,
                        "label": label,
                        "code": code,
                        "is_flawed": is_flawed
                    })
                except Exception as e:
                    print(f"Error reading {full_path}: {e}")
    return {"samples": data}

def save_json(data, output_file="parsed_cwe_data.json"):
    os.makedirs("datasets", exist_ok=True)
    out_path = os.path.join("datasets", output_file)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print("Saved parsed data to", out_path)

if __name__ == "__main__":
    extracted_path = "datasets/juliet/extracted/C/testcases"
    parsed_data = parse_source_files(extracted_path)
    save_json(parsed_data)