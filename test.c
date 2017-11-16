#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define MAX_NAME 32
#define SHA512 90

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

void readShadowFile(char *, User *);
void readLookupFile(char *, Lookup *);
void parseShadow(char *, User *);
void parsePasswd(char *, Lookup *);

int main(int argc, char const *argv[]) {
	if (argc != 3) {
		printf("Usage: %s <shadowfile> <lookup>\n", argv[0]);
		return 1;
	}
	time_t rawtime;
	struct tm * timeinfo;

	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "Program started at: %s", asctime(timeinfo) );

	readShadowFile(argv[1], shadowList); // read shadow file
	readLookupFile(argv[2], lookupList); // read lookup file

	time_t start = time(NULL);
	// Check if password hash is in lookup table
	for (tmpCreds = shadowList->nextNode; tmpCreds->nextNode != NULL; tmpCreds = tmpCreds->nextNode) {
		for (tmpLookup = lookupList->nextNode; tmpLookup->nextNode != NULL; tmpLookup = tmpLookup->nextNode) {
			if (strcmp(tmpCreds->hash, tmpLookup->hash) == 0) {
				tmpCreds->password = malloc(strlen(tmpLookup->plaintext) * sizeof(char));
				strcpy(tmpCreds->password, tmpLookup->plaintext);
				break;
			}
		}
		tmpLookup = lookupList;
	}
	printf("\nLookup Time: %f\n", (double)(time(NULL) - start));

	// Print out passwords
	for (tmpCreds = shadowList->nextNode; tmpCreds->nextNode != NULL; tmpCreds = tmpCreds->nextNode) {
		if (tmpCreds->password != NULL) {
			printf("user id : %s - password found => %s\n", tmpCreds->username, tmpCreds->password);
		} else {
			printf("user id : %s - password <NOT FOUND>\n", tmpCreds->username);
		}
	}

	// Print time
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "Program ended at: %s\n", asctime(timeinfo) );
	return 0;
}

// should add some format checks
void parsePasswd(char *string, Lookup *list) {

	// Do this if string passes format check
	char *plaintext;
	char *hash;
	char *token = strtok(string, ":");
	plaintext = malloc(strlen(token) * sizeof(char));
	strcpy(plaintext, token);
	token = strtok(NULL, ":");
	hash = malloc(strlen(token) * sizeof(char));
	strcpy(hash, token);
}

void parseShadow(char *string, User *list) {
	/*
	Pass in the array of hashes, return a populated array of Lookup
	if number of ':'s != 8 || number of '$'s != 3 print invalid entry
	if '$$' not found print salt not supported or account disabled
	*/

	// Do this if the string passes format check
	char *username;
	char *hash;
	char *token = strtok(string, ":");
	username = malloc(strlen(token) * sizeof(char));
	strcpy(username, token);
	token = strtok(NULL, ":");
	hash = malloc(strlen(token) * sizeof(char));
	strcpy(hash, token);
}

// Reads each line of the file into a array
void readShadowFile(char *name, User *array) {
	time_t start = time(NULL);
	FILE *fp = fopen(name, "r");	// get file pointer
	char * line = NULL;
	size_t len = 0;
	int lineLength;

	// check if file exists
	if (fp == NULL) {
		printf("Fatal error! %s is not found\n", name);
		printf("Program halted. Please verify the file path and try again.\n");
		exit(EXIT_FAILURE);
	}

	// store each line into a linked list node
	while ((lineLength = (int) getline(&line, &len, fp)) != -1) {
		line[strcspn(line,"\n")] = 0; // strip new line
		parseShadow(line, list);
	}

	free(line);
	// close file
	fclose(fp);
	printf("\nRead Time: %f\n", (double)(time(NULL) - start));
}

/*
Read all hashes into an array
*/
void readLookupFile(char *name, Lookup *array) {
	time_t start = time(NULL);
	FILE *fp = fopen(name, "r");	// get file pointer
	char * line = NULL;
	size_t len = 0;
	int lineLength;

	// check if file exists
	if (fp == NULL) {
		printf("Fatal error! %s is not found\n", name);
		printf("Program halted. Please verify the file path and try again.\n");
		exit(EXIT_FAILURE);
	}

	// store each line into a linked list node
	while ((lineLength = (int) getline(&line, &len, fp)) != -1) {
		line[strcspn(line,"\n")] = 0; // strip new line
	}

	free(line);
	// close file
	fclose(fp);
	printf("\nRead Time: %f\n", (double)(time(NULL) - start));
}
