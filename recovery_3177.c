/*
Author: David Zhu (P1703177)
Class: DISM/FT/1A/21
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "functions_3177.h"

struct User {
    char *username;
    char *hash;
    char *password;
};
typedef struct User User;

int pwFormatCheck(char *);
int shadowFormatCheck(char *);
void parseShadow(char *, User *);
void readShadowFile(FILE *, User *);
void readLookupFile(FILE *, Hash *);
unsigned long long countLines(FILE *);
void parsePasswd(char *, char *, Hash *);

/*  argv[1] is shadow file
    argv[2] is lookup file */
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <shadowfile> <lookup>\n", argv[0]);
        return 1;
    }
    FILE *shadowFP = is_valid_file(argv[1]); // get shadow file pointer
    FILE *lookupFP = is_valid_file(argv[2]); // get lookup file pointer
    char buf[26];
    time_t rawtime;
    struct tm * timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buf, 26, "%Y:%m:%d %H:%M:%S\n", timeinfo);
    printf("Program started at %s", buf);
    clock_t start = clock();

    unsigned long long shadowLength = countLines(shadowFP);      // get number of lines in shadow file
    unsigned long long lookupLength = countLines(lookupFP) / 2;  // get number of lines in lookup file

    Hash lookup[lookupLength];      // create lookup array
    User user[shadowLength];        // create user array

    printf("shadow entries: %llu\nlookup entries: %llu\n", shadowLength, lookupLength);

    readShadowFile(shadowFP, user);  // read shadow file into memory
    readLookupFile(lookupFP, lookup);// read lookup file into memory

    /* search for the password */
    for (int i = 0; i < shadowLength; i++) {
        if (user[i].username == NULL) continue;
        user[i].password = NULL;
        if (user[i].hash[1] == '1') { // if hash is md5
            for (int j = 0; j < lookupLength; j++) {
                if (lookup[j].md5 != NULL) {
                    if (strcmp(lookup[j].md5, user[i].hash) == 0) {
                        user[i].password = strdup(lookup[j].plaintext);
                        break;
                    }
                }
            }
        } else { // if hash is sha512
            for (int j = 0; j < lookupLength; j++) {
                if (lookup[j].sha512 != NULL) {
                    if (strcmp(lookup[j].sha512, user[i].hash) == 0) {
                        user[i].password = strdup(lookup[j].plaintext);
                        break;
                    }
                }
            }
        }
    }
    
    /* https://stackoverflow.com/questions/5248915/execution-time-of-c-program/5249150#5249150 */
    clock_t end = clock();
    double cpuTime = (double)(end - start) / CLOCKS_PER_SEC;

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
    /* https://stackoverflow.com/questions/3673226/how-to-print-time-in-format-2009-08-10-181754-811/3673291#3673291 */
    strftime(buf, 26, "%Y:%m:%d %H:%M:%S\n", timeinfo);
    printf("Program ended at %s", buf);
    printf("CPU time: %lf\n", cpuTime);
    fclose(shadowFP);
    fclose(lookupFP);
    return 0;
}

/* takes lookup table entry as arg
return 0 if valid, 1 if invalid */
int pwFormatCheck(char *string) {
    /* check number of ':' */
    int i = 0, count1 = 0, count2 = 0;
    while (string[i] != 0x0) {
        if (string[i] == ':')
            count1++;
        else if (string[i] == '$')
            count2++;
        i++;
    }
    if (count1 != 1) {
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

    return 0;
}

/* takes shadow entry as arg 
return 0 if valid, 1 if invalid */
int shadowFormatCheck(char *string) {
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

/* takes in md5 hash, sha512 hash and Hash struct as arg
stores md5 hash, sha512 hash and plaintext into the hash struct */
void parsePasswd(char *md5, char *sha512, Hash *lookup) {
    char *token;
    lookup->plaintext = NULL;
    if (pwFormatCheck(md5) != 1) {
        token = strtok(md5, ":");
        lookup->plaintext = strdup(token);
        token = strtok(NULL, ":");
        lookup->md5 = strdup(token);
    } else {
        lookup->md5 = NULL;
    }
    if (pwFormatCheck(sha512) != 1) {
        token = strtok(sha512, ":");
        if (lookup->plaintext == NULL)
            lookup->plaintext = strdup(token);
        token = strtok(NULL, ":");
        lookup->sha512 = strdup(token);
    } else {
        lookup->sha512 = NULL;
    }
}

/* takes in shadow entry and User struct 
parse shadow entry into user name and hash
and stores them into User struct */
void parseShadow(char *string, User *user) {
    if (shadowFormatCheck(string) == 1) {
        user->username = NULL;
        return;
    }

    // Do this if the string passes format check
    char *token = strtok(string, ":");
    user->username = strdup(token);
    token = strtok(NULL, ":");
    user->hash = strdup(token);
}

/* takes in file pointer as arg 
returns number of lines in a file */ 
unsigned long long countLines(FILE *fp) { 
    rewind(fp);
    char * line = NULL; 
    size_t len = 0; 
    unsigned long long count = 0; 
 
    while ((getline(&line, &len, fp)) != -1) { 
        count++; 
    } 
 
    return count; 
}

/* Read and parse the shadowfile 
takes in file pointer and array of User struct as arg*/
void readShadowFile(FILE *fp, User *array) {
    rewind(fp);
    char *line = NULL;
    size_t len = 0;
    unsigned long long i = 0;

    /* https://stackoverflow.com/questions/3501338/c-read-file-line-by-line/3501681#3501681 */
    while ((getline(&line, &len, fp)) != -1) {
        /* https://stackoverflow.com/questions/2693776/removing-trailing-newline-character-from-fgets-input/28462221#28462221 */
        line[strcspn(line,"\n")] = 0; // strip new line
        parseShadow(line, &array[i]);
        i++;
    }

    free(line);
}

/* Read and parse the lookup file 
takes in file pointer and array of Hash struct as arg*/
void readLookupFile(FILE *fp, Hash *array) {
    rewind(fp);
    char * line = NULL;
    size_t len = 0;
    unsigned long long i = 0, count = 0;
    char *prev, *current;

    /* https://stackoverflow.com/questions/3501338/c-read-file-line-by-line/3501681#3501681 */
    while ((getline(&line, &len, fp)) != -1) {
        /* https://stackoverflow.com/questions/2693776/removing-trailing-newline-character-from-fgets-input/28462221#28462221 */
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
}