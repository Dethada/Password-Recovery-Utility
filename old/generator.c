#include <stdio.h>
#include <string.h>
#include <crypt.h>
#include <stdlib.h>
#include <time.h>
#define MD5 26
#define SHA512 90

struct LinkedList
{
	char *md5;
	char *sha512;
	char *plaintext;
	struct LinkedList *nextNode;
};
typedef struct LinkedList LinkedList;

LinkedList *createNode(char *, int);
void appendNode(char *, int, LinkedList *);
LinkedList *readfile(char *, LinkedList *, int, int);
void writefile(char *, LinkedList *);

void printHelp(char *name) {
	printf("Usage: %s <wordlist> <min> <max>\n\n", name);
	printf("\t<wordlist> : A file path/name in which contains the password dictonary\n");
	printf("\t<min> : An integer value greater than 1.\n\t\tThis value represents the minimum length of the password.\n");
	printf("\t<max> : An integer value greater than or equals to <min>.\n\t\t<max> represents the maximum length of the password\n");
}

int main(int argc, char *argv[])
{
	if (argc != 4) {
		printHelp(argv[0]);
		return 1;
	} else if (atoi(argv[2]) > atoi(argv[3])) {
		printHelp(argv[0]);
		return 1;
	}

	clock_t start = clock();
	int min = atoi(argv[2]);
	int max = atoi(argv[3]);
	LinkedList *list = NULL;

	time_t start2 = time(NULL);
	list = readfile(argv[1], list, min, max);
	printf("\nRead Time: %f\n", (double)(time(NULL) - start2));

	if (list == NULL) {
		return 1;
	}

	char * md5_scheme = "$1$$";	 // type 1 implies md5 (number of iteration is only 1000 rounds)
	char * sha512_scheme = "$6$$";	 // type 2 implies sha-512 (default value as in yr 2017, number of iteration is minimum 10,000 rounds )
	LinkedList *tmp = list;

	clock_t start3 = clock();
	// Store hashes into linked list
	for (tmp = list->nextNode; tmp->nextNode != NULL; tmp = tmp->nextNode) {
		strcpy(tmp->md5, crypt(tmp->plaintext,md5_scheme)); // MD5 Hash
		strcpy(tmp->sha512, crypt(tmp->plaintext,sha512_scheme)); // SHA-512 Hash
	}
	strcpy(tmp->md5, crypt(tmp->plaintext,md5_scheme)); // MD5 Hash
	strcpy(tmp->sha512, crypt(tmp->plaintext,sha512_scheme)); // SHA-512 Hash
	clock_t end3 = clock();
	double execTime3 = (double)(end3 - start3) / CLOCKS_PER_SEC;
	printf("\nHash time: %lf\n", execTime3);

	// write hashes to file
	writefile("hashes.txt", list);

	// Print execution time
	clock_t end = clock();
	double execTime = (double)(end - start) / CLOCKS_PER_SEC;
	printf("\nTotal Execution time: %lf\n", execTime);
}

LinkedList *createNode(char *plaintext, int length) {
	LinkedList *newNode = malloc(sizeof(LinkedList));
	// Allocate memory for hash
	newNode->md5 = malloc(MD5 * sizeof(char));
	newNode->sha512 = malloc(SHA512 * sizeof(char));
	newNode->plaintext = malloc(length * sizeof(char));
	strcpy(newNode->plaintext, plaintext);
	newNode->nextNode = NULL;

	return newNode;
}

// length is size of plaintext
void appendNode(char *plaintext, int length, LinkedList *head) {
	LinkedList *newNode = malloc(sizeof(LinkedList));
	// Allocate memory for hash
	newNode->md5 = malloc(MD5 * sizeof(char));
	newNode->sha512 = malloc(SHA512 * sizeof(char));
	newNode->plaintext = malloc(length * sizeof(char));
	strcpy(newNode->plaintext, plaintext);
	newNode->nextNode = NULL;

	LinkedList *tmp = head;

	while (tmp->nextNode != NULL) {
		tmp = tmp->nextNode;
	}

	tmp->nextNode = newNode;
}

void writefile(char *name, LinkedList *head) {
	FILE *fp = fopen(name, "w");
	LinkedList *tmp = head->nextNode; // skip the starting node
	while (tmp-> nextNode != NULL) {
		fprintf(fp, "%s:%s\n%s:%s\n", tmp->plaintext, tmp->md5, tmp->plaintext, tmp->sha512);
		tmp = tmp->nextNode;
	}
	fprintf(fp, "%s:%s\n%s:%s\n", tmp->plaintext, tmp->md5, tmp->plaintext, tmp->sha512);
	fclose(fp);
}

LinkedList *readfile(char *name, LinkedList *list, int min, int max) {
	// get file pointer
	FILE *fp = fopen(name, "r");
	char * line = NULL;
	size_t len = 0;
	int read;
	unsigned long long count = 0; // number of words

	// check if file exists
	if (fp == NULL) {
		printf("Fatal error! %s is not found\n", name);
		printf("Program halted. Please verify the file path and try again.\n");
		return NULL;
	}
	list = createNode("start", 5) ; // create a starting node
	// store each line into a linked list node
	while ((read = (int) getline(&line, &len, fp)) != -1) {
		if (read < min || read > max)	continue;
		line[strcspn(line,"\n")] = 0; // strip new line
		appendNode(line, read, list); // add new node to list
		count++;
	}
	printf("Total number of words processed => %llu\n", count);
	printf("Total number of generated entries => %llu\n", count * 2);

	free(line);
	// close file
	fclose(fp);

	return list;
}
