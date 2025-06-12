import os
import shutil
import sys

def clean_datasets(base_dir="datasets"):
    """Clean all datasets directory contents"""
    if os.path.isdir(base_dir):
        print(f"Cleaning {base_dir}...")
        for entry in os.listdir(base_dir):
            path = os.path.join(base_dir, entry)
            if os.path.isdir(path):
                shutil.rmtree(path)
                print(f"  Removed directory: {entry}")
            elif os.path.isfile(path):
                os.remove(path)
                print(f"  Removed file: {entry}")
        print(f"✓ {base_dir} cleaned")
    else:
        print(f"Directory {base_dir} does not exist")

def clean_build(base_dir="build"):
    """Clean all build directory contents"""
    if os.path.isdir(base_dir):
        print(f"Cleaning {base_dir}...")
        for entry in os.listdir(base_dir):
            path = os.path.join(base_dir, entry)
            if os.path.isdir(path):
                shutil.rmtree(path)
                print(f"  Removed directory: {entry}")
            elif os.path.isfile(path):
                os.remove(path)
                print(f"  Removed file: {entry}")
        print(f"✓ {base_dir} cleaned")
    else:
        print(f"Directory {base_dir} does not exist")

def clean_stats(base_dir="stats"):
    """Clean generated statistics files but keep templates"""
    if os.path.isdir(base_dir):
        print(f"Cleaning {base_dir}...")
        files_to_remove = [
            "model_statistics.json",
            "enhanced_statistics.json",
            "archived_stats"
        ]
        for entry in files_to_remove:
            path = os.path.join(base_dir, entry)
            if os.path.isfile(path):
                os.remove(path)
                print(f"  Removed file: {entry}")
            elif os.path.isdir(path):
                shutil.rmtree(path)
                print(f"  Removed directory: {entry}")
        print(f"✓ {base_dir} cleaned")
    else:
        print(f"Directory {base_dir} does not exist")

def clean_cache(base_dir="cache"):
    """Clean cache directory"""
    if os.path.isdir(base_dir):
        print(f"Cleaning {base_dir}...")
        for entry in os.listdir(base_dir):
            path = os.path.join(base_dir, entry)
            if os.path.isdir(path):
                shutil.rmtree(path)
                print(f"  Removed directory: {entry}")
            elif os.path.isfile(path):
                os.remove(path)
                print(f"  Removed file: {entry}")
        print(f"✓ {base_dir} cleaned")
    else:
        print(f"Directory {base_dir} does not exist")

def clean_all():
    """Clean all generated files and directories"""
    print("=== Cleaning SuperDetector20000 ===")
    clean_datasets()
    clean_build()
    clean_stats()
    clean_cache()
    print("=== Cleanup completed ===")

def show_disk_usage():
    """Show disk usage of project directories"""
    print("\n=== Disk Usage ===")
    dirs_to_check = ["datasets", "build", "stats", "cache"]
    
    total_size = 0
    for dir_name in dirs_to_check:
        if os.path.isdir(dir_name):
            size = get_dir_size(dir_name)
            total_size += size
            print(f"{dir_name:12}: {format_size(size)}")
        else:
            print(f"{dir_name:12}: Not found")
    
    print(f"{'Total':12}: {format_size(total_size)}")

def get_dir_size(path):
    """Get directory size in bytes"""
    total = 0
    try:
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total += os.path.getsize(filepath)
    except Exception:
        pass
    return total

def format_size(bytes_size):
    """Format size in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} TB"

def confirm_action(message):
    """Ask for user confirmation"""
    while True:
        choice = input(f"{message} (y/n): ").lower().strip()
        if choice in ['y', 'yes']:
            return True
        elif choice in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' or 'n'")

def selective_clean():
    """Interactive cleanup menu"""
    while True:
        print("\n=== SuperDetector20000 Cleanup Menu ===")
        print("1. Clean datasets only")
        print("2. Clean build only")
        print("3. Clean stats only")
        print("4. Clean cache only")
        print("5. Clean all")
        print("6. Show disk usage")
        print("7. Exit")
        
        try:
            choice = input("\nChoice (1-7): ").strip()
            
            if choice == "1":
                if confirm_action("Clean datasets directory?"):
                    clean_datasets()
            elif choice == "2":
                if confirm_action("Clean build directory?"):
                    clean_build()
            elif choice == "3":
                if confirm_action("Clean stats directory?"):
                    clean_stats()
            elif choice == "4":
                if confirm_action("Clean cache directory?"):
                    clean_cache()
            elif choice == "5":
                if confirm_action("Clean ALL directories? This will remove all generated data!"):
                    clean_all()
            elif choice == "6":
                show_disk_usage()
            elif choice == "7":
                print("Cleanup cancelled")
                break
            else:
                print("Invalid choice. Please enter 1-7.")
                
        except KeyboardInterrupt:
            print("\nCleanup cancelled")
            break

def quick_clean():
    """Quick clean without confirmation - for automation"""
    print("=== Quick Clean Mode ===")
    clean_all()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--interactive":
            selective_clean()
        elif sys.argv[1] == "--quick":
            quick_clean()
        elif sys.argv[1] == "--usage":
            show_disk_usage()
        elif sys.argv[1] == "--help":
            print("Usage:")
            print("  python detect.py                 # Clean all (default)")
            print("  python detect.py --interactive   # Interactive menu")
            print("  python detect.py --quick         # Quick clean without confirmation")
            print("  python detect.py --usage         # Show disk usage")
            print("  python detect.py --help          # Show this help")
        else:
            print(f"Unknown option: {sys.argv[1]}")
            print("Use --help for usage information")
    else:
        clean_all()