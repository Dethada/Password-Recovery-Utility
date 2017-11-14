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
void readfile(char *, LinkedList *);
void parseShadow(char *, LinkedList *);
void parsePasswd(char *, LinkedList *);

int main(int argc, char const *argv[])
{
	if (argc != 2) {
		printf("Usage: %s <filename>\n", argv[0]);
		return 1;
	}
	LinkedList *lookupList = createNode(); // create starting node
	LinkedList *shadowList = createNode(); // create starting node
	printf("first addr: %p\n", shadowList);
	readfile(argv[1], shadowList);
	printf("second addr: %p\n", shadowList);
	printList(shadowList);
	return 0;
}

LinkedList *createNode() {
	LinkedList *newNode = malloc(sizeof(LinkedList));
	newNode->key = "start";
	newNode->hash = "nil";
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
}

// should add some format checks
void parsePasswd(char *string, LinkedList *list) {

	// Do this if string passes format check
	char *key;
	char *hash;
	char *token = strtok(string, ":");
	strcpy(key, token);
	token = strtok(NULL, ":");
	strcpy(hash, token);

	LinkedList *newNode = malloc(sizeof(LinkedList));
	newNode->key = malloc(strlen(key) * sizeof(char));
	newNode->hash = malloc(SHA512 * sizeof(char));
	strcpy(newNode->key, key);
	strcpy(newNode->hash, hash);
	newNode->nextNode = NULL;

	LinkedList *tmp = list;

	while (tmp->nextNode != NULL) {
		tmp = tmp->nextNode;
	}

	tmp->nextNode = newNode;
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
	strcpy(key, token);
	token = strtok(NULL, ":");
	strcpy(hash, token);
	printf("parseShadow addr: %p\n", list);
	LinkedList *newNode = malloc(sizeof(LinkedList));
	newNode->key = malloc(strlen(key) * sizeof(char));
	newNode->hash = malloc(SHA512 * sizeof(char));
	strcpy(newNode->key, key);
	strcpy(newNode->hash, hash);
	newNode->nextNode = NULL;

	LinkedList *tmp = list;
	printf("%p\n", tmp);
	while (tmp->nextNode != NULL) {
		printf("%p\n", tmp);
		tmp = tmp->nextNode;
	}

	tmp->nextNode = newNode;
}

// Reads each line of the file into a linked list
void readfile(char *name, LinkedList *list) {
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
		printf("readfile addr: %p\n", list);
		parseShadow(line, list);
	}

	free(line);
	// close file
	fclose(fp);
	printf("\nRead Time: %f\n", (double)(time(NULL) - start));
}
