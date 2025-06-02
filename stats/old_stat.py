import os
import sys
import json
import glob
import shutil
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

def archive_current_stats():
    """Archive les statistiques actuelles et le modèle .pkl avec le même nom"""
    try:
        base_dir = os.path.dirname(os.path.dirname(__file__))
        current_stats_path = os.path.join(base_dir, "stats/model_statistics.json")
        current_model_path = os.path.join(base_dir, "build/simple/cwe_model_latest.pkl")
        
        if not os.path.exists(current_stats_path):
            print("No current statistics to archive")
            return None
        
        # Lit les stats actuelles
        with open(current_stats_path, 'r') as f:
            stats = json.load(f)
        
        # Trouve le prochain numéro d'archive
        archives_dir = os.path.join(base_dir, "stats/archives")
        models_dir = os.path.join(base_dir, "build/simple/archived")
        os.makedirs(archives_dir, exist_ok=True)
        os.makedirs(models_dir, exist_ok=True)
        
        existing_archives = glob.glob(os.path.join(archives_dir, "model_statistics_*.json"))
        counter = len(existing_archives) + 1
        
        # Génère le nom de base pour l'archive
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"cwe_model_{counter:03d}_{timestamp}"
        
        # Archive les statistiques
        archive_stats_path = os.path.join(archives_dir, f"model_statistics_{counter:03d}_{timestamp}.json")
        
        # Ajoute des métadonnées d'archivage avec le nom du modèle
        stats['archived_at'] = datetime.now().isoformat()
        stats['archive_number'] = counter
        stats['model_file_name'] = f"{base_name}.pkl"
        
        with open(archive_stats_path, 'w') as f:
            json.dump(stats, f, indent=2)
        
        # Archive le modèle .pkl avec le même nom de base
        if os.path.exists(current_model_path):
            archive_model_path = os.path.join(models_dir, f"{base_name}.pkl")
            shutil.copy2(current_model_path, archive_model_path)
            print(f"Model archived: {archive_model_path}")
        
        print(f"Statistics archived: {archive_stats_path}")
        
        # Génère automatiquement l'index après archivage
        generate_archives_index()
        
        return archive_stats_path
        
    except Exception as e:
        print(f"Archive failed: {e}")
        return None

def list_archived_stats():
    """Liste toutes les statistiques archivées"""
    try:
        base_dir = os.path.dirname(os.path.dirname(__file__))
        archives_dir = os.path.join(base_dir, "stats/archives")
        
        if not os.path.exists(archives_dir):
            return []
        
        archives = []
        for file_path in sorted(glob.glob(os.path.join(archives_dir, "model_statistics_*.json"))):
            try:
                with open(file_path, 'r') as f:
                    stats = json.load(f)
                
                file_size = os.path.getsize(file_path)
                
                # Extrait le nom du modèle depuis les stats ou génère depuis le nom de fichier
                model_file_name = stats.get('model_file_name')
                if not model_file_name:
                    # Fallback: génère depuis le nom du fichier de stats
                    base_name = os.path.basename(file_path).replace('model_statistics_', '').replace('.json', '')
                    model_file_name = f"cwe_model_{base_name}.pkl"
                
                archives.append({
                    'file_path': file_path,
                    'file_name': os.path.basename(file_path),
                    'model_file_name': model_file_name,
                    'generated_at': stats.get('generated_at', 'Unknown'),
                    'archived_at': stats.get('archived_at', 'Unknown'),
                    'archive_number': stats.get('archive_number', 0),
                    'accuracy': stats.get('performance', {}).get('accuracy', 0),
                    'f1_score': stats.get('performance', {}).get('f1_score', 0),
                    'total_samples': stats.get('dataset', {}).get('total_samples', 0),
                    'file_size_kb': round(file_size / 1024, 1)
                })
            except:
                continue
        
        return archives
        
    except Exception as e:
        print(f"List archives failed: {e}")
        return []

def generate_archives_index():
    """Génère un index JSON de toutes les archives pour le site web"""
    try:
        base_dir = os.path.dirname(os.path.dirname(__file__))
        archives = list_archived_stats()
        
        # Transforme pour le web
        web_archives = []
        for archive in archives:
            # Vérifie si le modèle .pkl existe
            model_path = os.path.join(base_dir, "build/simple/archived", archive['model_file_name'])
            model_exists = os.path.exists(model_path)
            model_size = 0
            if model_exists:
                model_size = round(os.path.getsize(model_path) / (1024 * 1024), 1)  # MB
            
            web_archives.append({
                'name': archive['model_file_name'].replace('.pkl', ''),  # Nom sans extension
                'generated_date': archive['generated_at'][:10] if archive['generated_at'] != 'Unknown' else 'Unknown',
                'archived_date': archive['archived_at'][:10] if archive['archived_at'] != 'Unknown' else 'Unknown',
                'accuracy': f"{archive['accuracy']}%",
                'f1_score': archive['f1_score'],
                'samples': f"{archive['total_samples']:,}",
                'size': f"{model_size} MB" if model_exists else "N/A",
                'download_url': f"../build/simple/archived/{archive['model_file_name']}",
                'model_available': model_exists
            })
        
        index_path = os.path.join(base_dir, "stats/archives_index.json")
        with open(index_path, 'w') as f:
            json.dump({
                'generated_at': datetime.now().isoformat(),
                'total_archives': len(web_archives),
                'archives': web_archives
            }, f, indent=2)
        
        print(f"Archives index generated: {index_path}")
        return index_path
        
    except Exception as e:
        print(f"Index generation failed: {e}")
        return None

def cleanup_old_archives(keep_last_n=10):
    """Supprime les anciennes archives (garde les N dernières)"""
    try:
        base_dir = os.path.dirname(os.path.dirname(__file__))
        archives = list_archived_stats()
        if len(archives) <= keep_last_n:
            print(f"Only {len(archives)} archives, nothing to cleanup")
            return
        
        # Trie par numéro d'archive (plus récent en dernier)
        archives.sort(key=lambda x: x['archive_number'])
        
        # Supprime les plus anciens
        to_delete = archives[:-keep_last_n]
        deleted_count = 0
        
        for archive in to_delete:
            try:
                # Supprime le fichier de stats
                os.remove(archive['file_path'])
                
                # Supprime le modèle .pkl correspondant
                model_path = os.path.join(base_dir, "build/simple/archived", archive['model_file_name'])
                if os.path.exists(model_path):
                    os.remove(model_path)
                
                deleted_count += 1
                print(f"Deleted: {archive['file_name']} and {archive['model_file_name']}")
            except:
                continue
        
        print(f"Cleanup completed: {deleted_count} archives deleted")
        
        # Régénère l'index
        generate_archives_index()
        
    except Exception as e:
        print(f"Cleanup failed: {e}")

def update_old_stat_page():
    """Met à jour la page old_stat.html avec les dernières données"""
    try:
        generate_archives_index()
        print("Page old_stat.html updated with latest data")
        return True
    except Exception as e:
        print(f"Failed to update old_stat.html: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "archive":
            archive_current_stats()
        elif command == "list":
            archives = list_archived_stats()
            print(f"\n{len(archives)} archived statistics:")
            for a in archives:
                model_status = "✓" if os.path.exists(os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                                                  "build/simple/archived", a['model_file_name'])) else "✗"
                print(f"  {a['model_file_name']} {model_status} - {a['accuracy']}% accuracy - {a['generated_at'][:10]}")
        elif command == "index":
            generate_archives_index()
        elif command == "update":
            update_old_stat_page()
        elif command == "cleanup":
            keep_n = int(sys.argv[2]) if len(sys.argv) > 2 else 10
            cleanup_old_archives(keep_n)
        else:
            print("Usage: python old_stat.py [archive|list|index|update|cleanup]")
    else:
        print("Available commands:")
        print("  archive  - Archive current statistics and model")
        print("  list     - List all archived statistics")
        print("  index    - Generate web index of archives")
        print("  update   - Update old_stat.html page")
        print("  cleanup  - Remove old archives (keep last 10)")