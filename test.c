#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
void parsePasswd(char *, char *, Lookup *);
unsigned long long countLines(char *);

/* 	argv[1] is shadow file
	argv[2] is lookup file*/
int main(int argc, char *argv[]) {
	if (argc != 3) {
		printf("Usage: %s <shadowfile> <lookup>\n", argv[0]);
		return 1;
	}
	time_t rawtime;
	struct tm * timeinfo;

	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "Program started at: %s", asctime(timeinfo) );

	unsigned long long shadowLength = countLines(argv[1]); 		// get number of lines in shadow file
	unsigned long long lookupLength = countLines(argv[2]) / 2; 	// get number of lines in lookup file

	Lookup lookup[lookupLength];	// create lookup array
	User user[shadowLength];		// create user array

	printf("shadow: %llu\nlookup: %llu\n", shadowLength, lookupLength);

	readShadowFile(argv[1], user);	// read shadow file into memory
	readLookupFile(argv[2], lookup);// read lookup file into memory

	// printf("\n\n");
	// for (int i = 0; i < 4; i++) {
	// 	printf("%s:%s\n", lookup[i].plaintext, lookup[i].md5);
	// }

	/* search for the password */
	for (int i = 0; i < shadowLength; i++) {
		user[i].password = NULL;
		if (user[i].hash[1] == '1') { // if hash is md5
			for (int j = 0; j < lookupLength; j++) {
				if (strcmp(lookup[j].md5, user[i].hash) == 0) {
					user[i].password = strdup(lookup[j].plaintext);
					break;
				}
			}
		} else { // if hash is sha512
			for (int j = 0; j < lookupLength; j++) {
				if (strcmp(lookup[j].sha512, user[i].hash) == 0) {
					user[i].password = strdup(lookup[j].plaintext);
					break;
				}
			}
		}
	}

	/* Print out results */
	for (int i = 0; i < shadowLength; i++) {
		if (user[i].password != NULL) {
			printf("user id : %s - password found => %s\n", user[i].username, user[i].password);
		} else {
			printf("user id : %s - password <NOT FOUND>\n", user[i].username);
		}
	}

	// Print time
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "Program ended at: %s\n", asctime(timeinfo) );
	return 0;
}

/* should add some format checks */
void parsePasswd(char *md5, char *sha512, Lookup *lookup) {
	/* check if line has both plaintext and hash */


	// Do this if string passes format check
	char *token = strtok(md5, ":");
	lookup->plaintext = strdup(token);
	token = strtok(NULL, ":");
	lookup->md5 = strdup(token);
	token = strtok(sha512, ":");
	token = strtok(NULL, ":");
	lookup->sha512 = strdup(token);
}

void parseShadow(char *string, User *user) {
	/*
	Pass in the array of hashes, return a populated array of Lookup
	if number of ':'s != 8 || number of '$'s != 3 print invalid entry
	1 or 6 is not found after first $
	if '$$' not found print salt not supported or account disabled
	*/

	// Do this if the string passes format check
	char *token = strtok(string, ":");
	user->username = strdup(token);
	token = strtok(NULL, ":");
	user->hash = strdup(token);
}

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

/* Reads each line of the file into a array */
void readShadowFile(char *name, User *array) {
	FILE *fp = fopen(name, "r");	// get file pointer
	char * line = NULL;
	size_t len = 0;
	unsigned long long i = 0;

	// check if file exists
	if (fp == NULL) {
		printf("Fatal error! %s is not found\n", name);
		printf("Program halted. Please verify the file path and try again.\n");
		exit(EXIT_FAILURE);
	}

	// store each line into a linked list node
	while ((getline(&line, &len, fp)) != -1) {
		line[strcspn(line,"\n")] = 0; // strip new line
		parseShadow(line, &array[i]);
		i++;
	}

	free(line);
	// close file
	fclose(fp);
}

/* Read all hashes into an array */
void readLookupFile(char *name, Lookup *array) {
	FILE *fp = fopen(name, "r");	// get file pointer
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

	// store each line into a linked list node
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
	// close file
	fclose(fp);
}