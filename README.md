# SuperDetector20000

Détection automatique de vulnérabilités CWE dans du code C/C++.

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

1. **Lancer le programme principal :**
```bash
python main.py
```

2. **Suivre le pipeline automatique** (téléchargement dataset, entraînement, validation)

3. **Choisir une option :**
   - `1` : Menu de détection (tester des fichiers ou du code)
   - `2` : Quitter

## Menu de détection

Une fois dans le menu de détection :
- `1` : Tester un fichier C/C++
- `2` : Tester un snippet de code (coller le code puis taper `end`)
- `3` : Quitter

## Statistiques et performances

Consultez les métriques du modèle : https://pepitobailao.github.io/SuperDetector20000/

## Structure du projet

```
SuperDetector20000/
├── main.py              # Point d'entrée principal
├── src/simple/          # Code d'entraînement et détection
├── datasets/            # Datasets de vulnérabilités
├── build/simple/        # Modèles entraînés (.pkl)
└── stats/               # Statistiques et métriques
```