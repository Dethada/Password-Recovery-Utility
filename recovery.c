#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

struct Lookup {
    char *plaintext;
    char *md5;
    char *sha512;
};
struct User {
    char *username;
    char *hash;
    char *password;
};
typedef struct Lookup Lookup;
typedef struct User User;

int formatCheck(char *);
void parseShadow(char *, User *);
void readShadowFile(char *, User *);
void readLookupFile(char *, Lookup *);
void parsePasswd(char *, char *, Lookup *);
unsigned long long countLines(char *);

/*  argv[1] is shadow file
    argv[2] is lookup file */
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <shadowfile> <lookup>\n", argv[0]);
        return 1;
    }
    time_t rawtime;
    struct tm * timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    printf("Program started at: %s", asctime(timeinfo));
    clock_t begin = clock();

    unsigned long long shadowLength = countLines(argv[1]);      // get number of lines in shadow file
    unsigned long long lookupLength = countLines(argv[2]) / 2;  // get number of lines in lookup file

    Lookup lookup[lookupLength];    // create lookup array
    User user[shadowLength];        // create user array

    printf("shadow entries: %llu\nlookup entries: %llu\n", shadowLength, lookupLength);

    readShadowFile(argv[1], user);  // read shadow file into memory
    readLookupFile(argv[2], lookup);// read lookup file into memory

    /* search for the password */
    for (int i = 0; i < shadowLength; i++) {
        if (user[i].username == NULL)
            continue;
        user[i].password = NULL;
        if (user[i].hash[1] == '1') { // if hash is md5
            for (int j = 0; j < lookupLength; j++) {
                if (strcmp(lookup[j].md5, user[i].hash) == 0) {
                    user[i].password = strdup(lookup[j].plaintext);
                    break;
                }
            }
        } else {                    // if hash is sha512
            for (int j = 0; j < lookupLength; j++) {
                if (strcmp(lookup[j].sha512, user[i].hash) == 0) {
                    user[i].password = strdup(lookup[j].plaintext);
                    break;
                }
            }
        }
    }
    
    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

    /* Print out results */
    for (int i = 0; i < shadowLength; i++) {
        if (user[i].username == NULL) {
            printf("Data Error: Invalid entry found in the shadow file. (skipped)\n");
        } else if (user[i].password != NULL) {
            printf("user id : %s - password found => %s\n", user[i].username, user[i].password);
        } else {
            printf("user id : %s - password <NOT FOUND>\n", user[i].username);
        }
    }

    // Print time
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    printf("Program ended at: %s", asctime(timeinfo));
    printf("CPU time: %lf\n", time_spent);
    return 0;
}

/* store hashes into Lookup struct */
void parsePasswd(char *md5, char *sha512, Lookup *lookup) {

    char *token = strtok(md5, ":");
    lookup->plaintext = strdup(token);
    token = strtok(NULL, ":");
    lookup->md5 = strdup(token);
    token = strtok(sha512, ":");
    token = strtok(NULL, ":");
    lookup->sha512 = strdup(token);
}

/* checks format for shadow entry */
int formatCheck(char *string) {
    /* check number of ':' */
    int i = 0, count1 = 0, count2 = 0;
    while (string[i] != 0x0) {
        if (string[i] == ':')
            count1++;
        else if (string[i] == '$')
            count2++;
        i++;
    }
    if (count1 != 8) {
        return 1;
    } else if (count2 != 3) {
        return 1;
    }
    
    /* check if salt is empty and hash algo is supported*/
    char substr[5];
    char *p = strchr(string, '$');
    memcpy(substr, p, 4);
    substr[4] = 0x0;
    if (!(strcmp(substr, "$6$$") == 0 || strcmp(substr, "$1$$") == 0)) {
        return 1;
    }

    /* check hash length for the hash algo
    and hash does not contain illegal chars */
    for (i = 4;; i++) {
        char c = *(p+i);
        if (c == ':')
            break;
        if (!isalnum(c) && c != '.' && c != '/') {
            return 1;
        }
    }
    int length = i - 4;
    if (length != 22 && length != 86) {
        return 1;
    }
    
    /* check everything after pw field is numeric */
    p = p+i;
    i = 0;
    while (p[i] != 0x0) {
        if (!isdigit(p[i]) && p[i] != ':' && p[i] != '\n' && p[i] != 0xd) {
            return 1;
        }
        i++;
    }

    return 0;
}

/* gets username and hash from shadow entry */
void parseShadow(char *string, User *user) {
    if (formatCheck(string) == 1) {
        user->username = NULL;
        return;
    }

    // Do this if the string passes format check
    char *token = strtok(string, ":");
    user->username = strdup(token);
    token = strtok(NULL, ":");
    user->hash = strdup(token);
}

/* returns number of lines in a file */
unsigned long long countLines(char *name) {
    FILE *fp = fopen(name, "r");
    char * line = NULL;
    size_t len = 0;
    unsigned long long count = 0;

    while ((getline(&line, &len, fp)) != -1) {
        count++;
    }

    return count;
}

/* Read and parse the shadowfile */
void readShadowFile(char *name, User *array) {
    FILE *fp = fopen(name, "r");    // get file pointer
    char *line = NULL;
    size_t len = 0;
    unsigned long long i = 0;

    // check if file exists
    if (fp == NULL) {
        printf("Fatal error! %s is not found\n", name);
        printf("Program halted. Please verify the file path and try again.\n");
        exit(EXIT_FAILURE);
    }

    while ((getline(&line, &len, fp)) != -1) {
        line[strcspn(line,"\n")] = 0; // strip new line
        parseShadow(line, &array[i]);
        i++;
    }

    free(line);
    fclose(fp); // close file
}

/* Read and parse the lookup file */
void readLookupFile(char *name, Lookup *array) {
    FILE *fp = fopen(name, "r");    // get file pointer
    char * line = NULL;
    size_t len = 0;
    unsigned long long i = 0, count = 0;
    char *prev, *current;

    // check if file exists
    if (fp == NULL) {
        printf("Fatal error! %s is not found\n", name);
        printf("Program halted. Please verify the file path and try again.\n");
        exit(EXIT_FAILURE);
    }

    while ((getline(&line, &len, fp)) != -1) {
        line[strcspn(line,"\n")] = 0; // strip new line
        current = strdup(line);
        if (count % 2 != 0) {
            parsePasswd(prev, current, &array[i]);
            i++;
        }
        prev = strdup(current);
        count++;
    }

    free(line);
    fclose(fp); // close file
}