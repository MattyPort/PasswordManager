#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <regex.h>
#include <unistd.h> // for sleep function
#include <termios.h> 

#define MAX_PASSWORD_LENGTH 50
#define FILENAME "passwords.txt"
#define MASTER_PASSWORD_FILE "master_password.txt"
#define KEY_FILE "encryption_key.txt"
#define MAX_LOGIN_ATTEMPTS 3
#define LOCKOUT_TIME 60 // seconds

int loginAttempts = 0;

// Define a structure for password entry
typedef struct {
    char *username;
    char *encryptedPassword;
    char *website;
} PasswordEntry;

PasswordEntry *passwords = NULL;
int numPasswords = 0;

// Function declarations
void loadMasterPassword(char *masterPassword, const char *key);
void saveMasterPassword(const char *masterPassword, const char *key);
bool isSetupRequired();
void addPassword(const char *key);
void viewPasswords(const char *key, const char *masterPassword);
void editPassword(const char *key, const char *masterPassword);
void deletePassword(const char *key, const char *masterPassword);
void changeMasterPassword(char *masterPassword, const char *key);
void generateRandomKey(char *key);
void loadKeyFromFile(char *key);
void saveKeyToFile(const char *key);

void getPasswordInput(char *password, int maxLength) {
    struct termios old, new;
    tcgetattr(fileno(stdin), &old);
    new = old;
    new.c_lflag &= ~ECHO;
    tcsetattr(fileno(stdin), TCSANOW, &new);
    fgets(password, maxLength, stdin);
    password[strcspn(password, "\n")] = '\0'; // remove newline
    tcsetattr(fileno(stdin), TCSANOW, &old);
}

void encryptPassword(const char *password, const char *key, char *encryptedPassword) {
    int keyLen = strlen(key);
    int passwordLen = strlen(password);
    for (int i = 0; i < passwordLen; i++) {
        encryptedPassword[i] = ((password[i] - ' ') + (key[i % keyLen] - ' ')) % 95 + ' ';
    }
    encryptedPassword[passwordLen] = '\0'; //null terminator
}

void decryptPassword(const char *encryptedPassword, const char *key, char *decryptedPassword) {
    int keyLen = strlen(key);
    int encryptedLen = strlen(encryptedPassword);
    for (int i = 0; i < encryptedLen; i++) {
        decryptedPassword[i] = ((encryptedPassword[i] - ' ') - (key[i % keyLen] - ' ') + 95) % 95 + ' ';
    }
    decryptedPassword[encryptedLen] = '\0';
}

void encryptMasterPassword(const char *password, const char *key, char *encryptedPassword) {
    int keyLen = strlen(key);
    int passwordLen = strlen(password);
    for (int i = 0; i < passwordLen; i++) {
        encryptedPassword[i] = ((password[i] - ' ') + (key[i % keyLen] - ' ')) % 95 + ' ';
    }
    encryptedPassword[passwordLen] = '\0';
}

void decryptMasterPassword(const char *encryptedPassword, const char *key, char *decryptedPassword) {
    int keyLen = strlen(key);
    int encryptedLen = strlen(encryptedPassword);
    for (int i = 0; i < encryptedLen; i++) {
        decryptedPassword[i] = ((encryptedPassword[i] - ' ') - (key[i % keyLen] - ' ') + 95) % 95 + ' ';
    }
    decryptedPassword[encryptedLen] = '\0';
}

void saveMasterPassword(const char *masterPassword, const char *key) {
    char encryptedPassword[MAX_PASSWORD_LENGTH];
    encryptMasterPassword(masterPassword, key, encryptedPassword);

    FILE *file = fopen(MASTER_PASSWORD_FILE, "w");
    if (file != NULL) {
        fprintf(file, "%s", encryptedPassword);
        fclose(file);
    }
}

void loadMasterPassword(char *masterPassword, const char *key) {
    FILE *file = fopen(MASTER_PASSWORD_FILE, "r");
    if (file != NULL) {
        fscanf(file, "%s", masterPassword);
        fclose(file);
        decryptMasterPassword(masterPassword, key, masterPassword);
    }
}

int authenticateMasterPassword(const char *masterPassword) {
    char enteredPassword[MAX_PASSWORD_LENGTH];
    printf("Enter master password: ");
    getPasswordInput(enteredPassword, MAX_PASSWORD_LENGTH);
    if (strcmp(enteredPassword, masterPassword) == 0) {
        loginAttempts = 0; // Reset login attempts on successful login
        return 1;
    } else {
        loginAttempts++;
        if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
            printf("Too many failed attempts. Account locked. Please try again after %d seconds.\n", LOCKOUT_TIME);
            sleep(LOCKOUT_TIME);
            loginAttempts = 0; // Reset login attempts after lockout
        } else {
            printf("Incorrect password. You have %d attempts left.\n", MAX_LOGIN_ATTEMPTS - loginAttempts);
        }
        return 0;
    }
}

void generateRandomKey(char *key) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int charsetSize = sizeof(charset) - 1;

    srand(time(NULL));
    for (int i = 0; i < MAX_PASSWORD_LENGTH - 1; i++) {
        key[i] = charset[rand() % charsetSize];
    }
    key[MAX_PASSWORD_LENGTH - 1] = '\0';
}

void loadKeyFromFile(char *key) {
    FILE *file = fopen(KEY_FILE, "r");
    if (file != NULL) {
        fscanf(file, "%s", key);
        fclose(file);
    } else {
        printf("Encryption key file not found. Generating a new one...\n");
        generateRandomKey(key);
        saveKeyToFile(key);
        printf("Encryption key generated and saved to file.\n");
    }
}

void saveKeyToFile(const char *key) {
    FILE *file = fopen(KEY_FILE, "w");
    if (file != NULL) {
        fprintf(file, "%s", key);
        fclose(file);
    } else {
        printf("Error: Could not save encryption key.\n");
        exit(1);
    }
}

void loadPasswords(const char *key) {
    FILE *file = fopen(FILENAME, "r");
    if (file == NULL) {
        printf("No passwords found.\n");
        return;
    }

    char username[MAX_PASSWORD_LENGTH];
    char encryptedPassword[MAX_PASSWORD_LENGTH];
    char website[MAX_PASSWORD_LENGTH];

    while (fscanf(file, "%s %s %s", username, encryptedPassword, website) != EOF) {
        // Allocate memory for username, password, and website
        passwords = realloc(passwords, (numPasswords + 1) * sizeof(PasswordEntry));
        if (passwords == NULL) {
            printf("Memory allocation failed.\n");
            exit(1);
        }

        passwords[numPasswords].username = malloc(MAX_PASSWORD_LENGTH * sizeof(char));
        passwords[numPasswords].encryptedPassword = malloc(MAX_PASSWORD_LENGTH * sizeof(char));
        passwords[numPasswords].website = malloc(MAX_PASSWORD_LENGTH * sizeof(char));

        strcpy(passwords[numPasswords].username, username);
        strcpy(passwords[numPasswords].encryptedPassword, encryptedPassword);
        strcpy(passwords[numPasswords].website, website);

        numPasswords++;
    }

    fclose(file);
}

void savePasswords(const char *key) {
    FILE *file = fopen(FILENAME, "w");
    if (file == NULL) {
        printf("Error saving passwords.\n");
        return;
    }

    for (int i = 0; i < numPasswords; i++) {
        fprintf(file, "%s %s %s\n", passwords[i].username, passwords[i].encryptedPassword, passwords[i].website);
    }

    fclose(file);
}

void addPassword(const char *key) {
    char input[MAX_PASSWORD_LENGTH];

    // Allocate memory for new password entry
    passwords = realloc(passwords, (numPasswords + 1) * sizeof(PasswordEntry));
    if (passwords == NULL) {
        printf("Memory allocation failed.\n");
        exit(1);
    }

    // Allocate memory for username, password, and website
    passwords[numPasswords].username = malloc(MAX_PASSWORD_LENGTH * sizeof(char));
    passwords[numPasswords].encryptedPassword = malloc(MAX_PASSWORD_LENGTH * sizeof(char));
    passwords[numPasswords].website = malloc(MAX_PASSWORD_LENGTH * sizeof(char));

    printf("Enter username: ");
    scanf("%s", input);
    if (strlen(input) == 0) {
        printf("Username cannot be empty. Please try again.\n");
        return;
    }
    strcpy(passwords[numPasswords].username, input);

    printf("Enter password: ");
    scanf("%s", input);
    if (strlen(input) == 0) {
        printf("Password cannot be empty. Please try again.\n");
        return;
    }
    encryptPassword(input, key, passwords[numPasswords].encryptedPassword);

    printf("Enter website: ");
    scanf("%s", input);
    if (strlen(input) == 0) {
        printf("Website cannot be empty. Please try again.\n");
        return;
    }
    strcpy(passwords[numPasswords].website, input);

    numPasswords++;
    printf("Password added successfully.\n");

    savePasswords(key);
}

void viewPasswords(const char *key, const char *masterPassword) {
    if (!authenticateMasterPassword(masterPassword)) {
        printf("Authentication failed.\n");
        return;
    }

    if (numPasswords == 0) {
        printf("No passwords found.\n");
        return;
    }

    char searchWebsite[MAX_PASSWORD_LENGTH];
    printf("\nEnter the website to view passwords: ");
    scanf("%s", searchWebsite);

    regex_t regex;
    int reti = regcomp(&regex, searchWebsite, 0);
    if (reti != 0) {
        printf("Invalid regular expression.\n");
        return;
    }

    printf("Passwords matching '%s':\n", searchWebsite);
    bool found = false;
    for (int i = 0; i < numPasswords; i++) {
        reti = regexec(&regex, passwords[i].website, 0, NULL, 0);
        if (reti == 0) {
            char decryptedPassword[MAX_PASSWORD_LENGTH];
            decryptPassword(passwords[i].encryptedPassword, key, decryptedPassword);
            printf("Username: %s, Password: %s\n", passwords[i].username, decryptedPassword);
            found = true;
        }
    }

    if (!found) {
        printf("No passwords found matching '%s'.\n", searchWebsite);
    }

    regfree(&regex);
}

void editPassword(const char *key, const char *masterPassword) {
    if (!authenticateMasterPassword(masterPassword)) {
        printf("Authentication failed.\n");
        return;
    }

    if (numPasswords == 0) {
        printf("No passwords found.\n");
        return;
    }

    char searchWebsite[MAX_PASSWORD_LENGTH];
    printf("\nEnter the website of the password to edit: ");
    scanf("%s", searchWebsite);

    int index = -1;
    int count = 0;
    int foundIndexes[numPasswords];
    
    for (int i = 0; i < numPasswords; i++) {
        if (strcmp(passwords[i].website, searchWebsite) == 0) {
            foundIndexes[count++] = i;
        }
    }

    if (count == 0) {
        printf("Password not found.\n");
        return;
    } else if (count == 1) {
        index = foundIndexes[0];
    } else {
        printf("Multiple passwords found for website '%s':\n", searchWebsite);
        for (int i = 0; i < count; i++) {
            printf("%d. Username: %s\n", i + 1, passwords[foundIndexes[i]].username);
        }
        printf("Enter the number of the password to edit: ");
        int choice;
        scanf("%d", &choice);
        if (choice < 1 || choice > count) {
            printf("Invalid choice.\n");
            return;
        }
        index = foundIndexes[choice - 1];
    }

    char input[MAX_PASSWORD_LENGTH];

    printf("Enter new username: ");
    scanf("%s", input);
    if (strlen(input) == 0) {
        printf("Username cannot be empty. Please try again.\n");
        return;
    }
    strcpy(passwords[index].username, input);

    printf("Enter new password: ");
    scanf("%s", input);
    if (strlen(input) == 0) {
        printf("Password cannot be empty. Please try again.\n");
        return;
    }
    encryptPassword(input, key, passwords[index].encryptedPassword);

    printf("Enter new website: ");
    scanf("%s", input);
    if (strlen(input) == 0) {
        printf("Website cannot be empty. Please try again.\n");
        return;
    }
    strcpy(passwords[index].website, input);

    printf("Password updated successfully.\n");

    savePasswords(key);
}

void deletePassword(const char *key, const char *masterPassword) {
    if (!authenticateMasterPassword(masterPassword)) {
        printf("Authentication failed.\n");
        return;
    }

    if (numPasswords == 0) {
        printf("No passwords found.\n");
        return;
    }

    char searchWebsite[MAX_PASSWORD_LENGTH];
    printf("\nEnter the website of the password to delete: ");
    scanf("%s", searchWebsite);

    int count = 0;
    int foundIndexes[numPasswords];
    
    // Find all passwords with the given website
    for (int i = 0; i < numPasswords; i++) {
        if (strcmp(passwords[i].website, searchWebsite) == 0) {
            foundIndexes[count++] = i;
        }
    }

    if (count == 0) {
        printf("No passwords found for website '%s'.\n", searchWebsite);
        return;
    } else {
        printf("Passwords found for website '%s':\n", searchWebsite);
        for (int i = 0; i < count; i++) {
            char decryptedPassword[MAX_PASSWORD_LENGTH];
            decryptPassword(passwords[foundIndexes[i]].encryptedPassword, key, decryptedPassword);
            printf("%d. Username: %s, Password: %s\n", i + 1, passwords[foundIndexes[i]].username, decryptedPassword);
        }
    }

    printf("Enter the number of the password to delete: ");
    int choice;
    scanf("%d", &choice);
    if (choice < 1 || choice > count) {
        printf("Invalid choice.\n");
        return;
    }
    
    // Delete the chosen password
    int index = foundIndexes[choice - 1];
    free(passwords[index].username);
    free(passwords[index].encryptedPassword);
    free(passwords[index].website);

    for (int i = index; i < numPasswords - 1; i++) {
        passwords[i] = passwords[i + 1];
    }
    numPasswords--;

    printf("Password deleted successfully.\n");

    savePasswords(key);
}

void changeMasterPassword(char *masterPassword, const char *key) {
    if (!authenticateMasterPassword(masterPassword)) {
        printf("Authentication failed.\n");
        return;
    }

    char newMasterPassword[MAX_PASSWORD_LENGTH];
    char retypePassword[MAX_PASSWORD_LENGTH];
    do {
        printf("\nEnter new master password: ");
        getPasswordInput(newMasterPassword, MAX_PASSWORD_LENGTH);
        if (strlen(newMasterPassword) == 0) {
            printf("Empty password. Please try again.\n");
            continue;
        }
        printf("Retype new master password: ");
        getPasswordInput(retypePassword, MAX_PASSWORD_LENGTH);
        if (strcmp(newMasterPassword, retypePassword) != 0) {
            printf("Passwords do not match. Please try again.\n");
        }
    } while (strcmp(newMasterPassword, retypePassword) != 0);

    strcpy(masterPassword, newMasterPassword);
    saveMasterPassword(masterPassword, key); 
    printf("Master password changed successfully.\n");
}

bool isSetupRequired() {
    FILE *file = fopen(FILENAME, "r");
    if (file == NULL) {
        fclose(file);
        return true;
    }
    fclose(file);
    return false;
}

int main() {
    char masterPassword[MAX_PASSWORD_LENGTH];
    char encryptionKey[MAX_PASSWORD_LENGTH];
    char retypePassword[MAX_PASSWORD_LENGTH];

    loadKeyFromFile(encryptionKey); // Load or generate encryption key

    loadMasterPassword(masterPassword, encryptionKey); // Load master password

    if (isSetupRequired()) {
      printf("\n╭━━━╮╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱/╭╮╭━╮╭━╮\n");
        printf("┃╭━╮┃╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱/┃┃┃┃╰╯┃┃\n");
        printf("┃╰━╯┣━━┳━━┳━━┳╮╭╮╭┳━━┳━┳━╯┃┃╭╮╭╮┣━━┳━╮╭━━┳━━┳━━┳━╮\n");
        printf("┃╭━━┫╭╮┃━━┫━━┫╰╯╰╯┃╭╮┃╭┫╭╮┃┃┃┃┃┃┃╭╮┃╭╮┫╭╮┃╭╮┃┃━┫╭╯\n");
        printf("┃┃╱╱┃╭╮┣━━┣━━┣╮╭╮╭┫╰╯┃┃┃╰╯┃┃┃┃┃┃┃╭╮┃┃┃┃╭╮┃╰╯┃┃━┫┃\n");
        printf("╰╯╱╱╰╯╰┻━━┻━━╯╰╯╰╯╰━━┻╯╰━━╯╰╯╰╯╰┻╯╰┻╯╰┻╯╰┻━╮┣━━┻╯\n");
        printf("╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╭━╯┃\n");
        printf("╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱/╰━━╯\n\n");


        printf("Welcome! It seems you're a new user.\n");
        printf("[1] About\n");
        printf("[2] Set up Master Password\n");

        int setupChoice;
        printf("Enter your choice: ");
        scanf("%d", &setupChoice);
        while (getchar() != '\n'); // Clear input buffer

        switch (setupChoice) {
            case 1:
                printf("\nThis is a simple password manager program written in C.\n");
                printf("It allows you to store and manage your passwords securely.\n\n");
                printf("Frequently Asked Questions (FAQs):\n");
                printf("1. What is a master password?\n");
                printf("   A master password is a single password that you use to access all of the passwords stored in this program. It's like the key to a safe containing all your passwords.\n\n");
                printf("2. How does the encryption work?\n");
                printf("   The program encrypts your passwords using a key. When you enter a password, it gets encrypted using the key before being stored. When you retrieve a password, it gets decrypted using the same key.\n\n");
                printf("3. What if I forget my master password?\n");
                printf("   Unfortunately, if you forget your master password, there's no way to recover it. You'll lose access to all the passwords stored in this program. Make sure to remember your master password or keep it in a safe place.\n\n");
                printf("[1] Go back\n");
                int aboutChoice;
                printf("Enter your choice: ");
                scanf("%d", &aboutChoice);
                while (getchar() != '\n'); // Clear input buffer
                if (aboutChoice == 1) {
                    main(); // Go back to the main menu
                    return 0;
                } else {
                    printf("Invalid choice. Going back to the main menu.\n");
                    break;
                }
            case 2:
                printf("\nEnter your master password: ");
                getPasswordInput(masterPassword, MAX_PASSWORD_LENGTH);
                printf("\nRetype your master password: ");
                getPasswordInput(retypePassword, MAX_PASSWORD_LENGTH);
                if (strcmp(masterPassword, retypePassword) != 0) {
                    printf("\nPasswords do not match. Please try again.\n");
                    break;
                }
                saveMasterPassword(masterPassword, encryptionKey); // Save master password encrypted with the key
                printf("\nMaster password set successfully.\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }

    loadPasswords(encryptionKey); // Load passwords from file when the program starts

    int choice;

    do {
        printf("\n[1] Add Password\n[2] View Passwords\n[3] Edit Password\n[4] Delete Password\n[5] Change Master Password\n[6] Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        // Clear input buffer
        while (getchar() != '\n');

        switch (choice) {
            case 1:
                addPassword(encryptionKey);
                break;
            case 2:
                if (authenticateMasterPassword(masterPassword)) {
                    viewPasswords(encryptionKey, masterPassword);
                }
                break;
            case 3:
                if (authenticateMasterPassword(masterPassword)) {
                    editPassword(encryptionKey, masterPassword);
                }
                break;
            case 4:
                if (authenticateMasterPassword(masterPassword)) {
                    deletePassword(encryptionKey, masterPassword);
                }
                break;
            case 5:
                changeMasterPassword(masterPassword, encryptionKey);
                break;
            case 6:
                printf("Exiting program.\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    } while (choice != 6);

    // Free dynamically allocated memory
    for (int i = 0; i < numPasswords; i++) {
        free(passwords[i].username);
        free(passwords[i].encryptedPassword);
        free(passwords[i].website);
    }
    free(passwords);

    return 0;
}

