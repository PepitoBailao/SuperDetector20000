import os
import shutil

def netoyage_dataset(base_dir="datasets"):
    # remove all subdirectories
    for entry in os.listdir(base_dir):
        path = os.path.join(base_dir, entry)
        if os.path.isdir(path):
            shutil.rmtree(path)
            print(f"Dossier supprimé : {entry}")
    # remove parsed_cwe_data.json if exists
    json_path = os.path.join(base_dir, "parsed_cwe_data.json")
    if os.path.isfile(json_path):
        os.remove(json_path)
        print("Fichier supprimé : parsed_cwe_data.json")
    print("Nettoyage terminé.")

if __name__ == "__main__":
    netoyage_dataset()