#include <stdio.h>

int main() {
    char data[5];
    int input = 0;

    printf("Entrez un nombre entre 0 et 255 : ");
    scanf("%d", &input);

    // Vulnérabilité CWE-464 : ajout involontaire de '\0' (valeur 0) dans une chaîne
    // Si l'utilisateur entre 0, cela insère un caractère nul dans la structure
    data[0] = (char)input;
    data[1] = 'A';
    data[2] = 'B';
    data[3] = 'C';
    data[4] = '\0';

    printf("Contenu : %s\n", data);

    return 0;
}
