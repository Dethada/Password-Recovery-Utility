#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define MAX_NAME 32
#define SHA512 90

struct LinkedList
{
	char *key;
	char *hash;
	struct LinkedList *nextNode;
};
typedef struct LinkedList LinkedList;

LinkedList *createNode();
void appendNode(char *, char *, int, LinkedList *);
void printList(LinkedList *);
void readfile(char *, LinkedList *, int);
void parseShadow(char *, LinkedList *);
void parsePasswd(char *, LinkedList *);

int main(int argc, char const *argv[])
{
	if (argc != 3) {
		printf("Usage: %s <shadowfile> <lookup>\n", argv[0]);
		return 1;
	}
	time_t rawtime;
	struct tm * timeinfo;

	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "Program started at: %s", asctime(timeinfo) );
	LinkedList *lookupList = createNode(); // create starting node
	LinkedList *shadowList = createNode(); // create starting node
	readfile(argv[1], shadowList, 0); // read shadow file
	readfile(argv[2], lookupList, 1); // read lookup file
	printList(shadowList);
	printf("-------------------------------\n");
	printList(lookupList);

	appendNode("end", "", 3, shadowList); // add ending node
	appendNode("end", "", 3, lookupList); // add ending node
	LinkedList *tmpCreds = shadowList;
	LinkedList *tmpLookup = lookupList;

	time_t start = time(NULL);
	// Store hashes into linked list
	for (tmpCreds = tmpCreds->nextNode; tmpCreds->nextNode != NULL; tmpCreds = tmpCreds->nextNode) {
		for (tmpLookup = tmpLookup->nextNode; tmpLookup->nextNode != NULL; tmpLookup = tmpLookup->nextNode) {
			if (strcmp(tmpCreds->hash, tmpLookup->hash) == 0) {
				printf("user id : %s - password found => %s\n", tmpCreds->key, tmpLookup->key);
				break;
			}
		}
		tmpLookup = lookupList;
	}
	printf("\nLookup Time: %f\n", (double)(time(NULL) - start));

	// Print time
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "Program ended at: %s\n", asctime(timeinfo) );
	return 0;
}

LinkedList *createNode() {
	LinkedList *newNode = malloc(sizeof(LinkedList));
	newNode->nextNode = NULL;

	return newNode;
}

// length is size of key
void appendNode(char *key, char *hash, int length, LinkedList *head) {
	LinkedList *newNode = malloc(sizeof(LinkedList));
	newNode->key = malloc(length * sizeof(char));
	newNode->hash = malloc(SHA512 * sizeof(char));
	strcpy(newNode->key, key);
	strcpy(newNode->hash, hash);
	newNode->nextNode = NULL;

	LinkedList *tmp = head;

	while (tmp->nextNode != NULL) {
		tmp = tmp->nextNode;
	}

	tmp->nextNode = newNode;
}

void printList(LinkedList *head) {
	LinkedList *tmp = head->nextNode;

	while (tmp->nextNode != NULL) {
		printf("%s:%s\n", tmp->key, tmp->hash);
		tmp = tmp->nextNode;
	}
	printf("%s:%s\n", tmp->key, tmp->hash);
}

// should add some format checks
void parsePasswd(char *string, LinkedList *list) {

	// Do this if string passes format check
	char *key;
	char *hash;
	char *token = strtok(string, ":");
	key = malloc(strlen(token) * sizeof(char));
	strcpy(key, token);
	token = strtok(NULL, ":");
	hash = malloc(strlen(token) * sizeof(char));
	strcpy(hash, token);
	appendNode(key, hash, strlen(key), list);
}

void parseShadow(char *string, LinkedList *list) {
	/*
	if number of ':'s != 8 || number of '$'s != 3 print invalid entry
	if '$$' not found print salt not supported or account disabled
	*/

	// Do this if the string passes format check
	char *key;
	char *hash;
	char *token = strtok(string, ":");
	key = malloc(strlen(token) * sizeof(char));
	strcpy(key, token);
	token = strtok(NULL, ":");
	hash = malloc(strlen(token) * sizeof(char));
	strcpy(hash, token);
	appendNode(key, hash, strlen(key), list);
}

// Reads each line of the file into a linked list
// mode = 0 for shadow file mode, mode = 1 for lookup table mode
void readfile(char *name, LinkedList *list, int mode) {
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

	if (mode == 0) {
		// store each line into a linked list node
		while ((lineLength = (int) getline(&line, &len, fp)) != -1) {
			line[strcspn(line,"\n")] = 0; // strip new line
			parseShadow(line, list);
		}
	} else {
		// store each line into a linked list node
		while ((lineLength = (int) getline(&line, &len, fp)) != -1) {
			line[strcspn(line,"\n")] = 0; // strip new line
			parsePasswd(line, list);
		}
	}

	free(line);
	// close file
	fclose(fp);
	printf("\nRead Time: %f\n", (double)(time(NULL) - start));
}
