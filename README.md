# Détection automatique de CWE dans du code C/C++

## Structure

- `main.py` : entraînement du modèle sur Juliet.
- `detecteur.py` : prédiction de CWE à partir d’un fichier `.c`.
- `dataset.py` : téléchargement et parsing de Juliet.
- `classifier.py` : pipeline de classification (TF-IDF + Naive Bayes).
- `nettoyage.py` : nettoyage du code (suppression de commentaires, etc.).
- `cleaner.py` ; permet de supprimer tous les fichier dans dataset pour les tests
- `helper.py` : fonction utilitaires partagées

## Utilisation

1. **Installer les dépendances**

```bash
pip install -r requirements.txt
