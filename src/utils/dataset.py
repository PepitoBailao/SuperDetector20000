import os
import urllib.request
import zipfile
from urllib.error import HTTPError

def download_dataset(download_url, dataset_name, base_dir="datasets"):
    dataset_dir = os.path.join(base_dir, dataset_name)
    if not os.path.exists(dataset_dir):
        os.makedirs(dataset_dir)
    zip_path = os.path.join(dataset_dir, f"{dataset_name}.zip")
    
    # Téléchargement du fichier zip si non présent
    if not os.path.exists(zip_path):
        print(f"Téléchargement du dataset {dataset_name} ...")
        try:
            urllib.request.urlretrieve(download_url, zip_path)
            print("Téléchargement terminé.")
        except HTTPError as e:
            print(f"Erreur lors du téléchargement de {dataset_name} : {e}")
            return None
    else:
        print(f"Le fichier zip de {dataset_name} existe déjà.")

    # Extraction de tous les fichiers zip dans le dossier du dataset
    extracted_path = extract_all_zip_files(dataset_dir)
    
    return extracted_path

def extract_all_zip_files(dataset_dir, extraction_folder="extracted"):
    """
    Parcourt le dossier dataset_dir et extrait tous les fichiers .zip
    dans un sous-dossier 'extracted' en créant un dossier pour chaque zip.
    """
    extracted_root = os.path.join(dataset_dir, extraction_folder)
    if not os.path.exists(extracted_root):
        os.makedirs(extracted_root)
    
    # Liste tous les fichiers zip dans dataset_dir
    zip_files = [f for f in os.listdir(dataset_dir) if f.lower().endswith('.zip')]
    if not zip_files:
        print("Aucun fichier zip trouvé pour extraction.")
        return extracted_root
    
    for zip_file in zip_files:
        zip_file_path = os.path.join(dataset_dir, zip_file)
        # Dossier de destination pour ce zip (nommé d'après le zip)
        unzip_target = os.path.join(extracted_root, zip_file[:-4])
        if not os.path.exists(unzip_target):
            os.makedirs(unzip_target)
            print(f"Extraction de {zip_file} dans {unzip_target} ...")
            with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
                zip_ref.extractall(unzip_target)
            print(f"Extraction terminée pour {zip_file}.")
        else:
            print(f"{zip_file} a déjà été extrait dans {unzip_target}.")
    
    return extracted_root

# Exemple d'utilisation pour plusieurs datasets
if __name__ == "__main__":
    datasets = {
        "juliet": "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip",
        "SATE6": "https://samate.nist.gov/SARD/downloads/test-suites/2024-08-26-sakai-sate6-v11-2.zip"
        
        # Vous pouvez ajouter d'autres datasets ici :
        # "autre_dataset": "URL_DU_DATASET",
    }
    
    for name, url in datasets.items():
        path = download_dataset(url, name)
        if path:
            print(f"Dataset '{name}' disponible dans : {path}")
        else:
            print(f"Échec pour le dataset '{name}'.")