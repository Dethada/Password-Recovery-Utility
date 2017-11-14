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
LinkedList *appendNode(char *, int, LinkedList *);
void printList(LinkedList *);
LinkedList *readfile(char *, LinkedList *);
void writefile(char *, char *, unsigned long long);

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Usage: %s <filename>\n", argv[0]);
		return 1;
	}
	clock_t start = clock();
	LinkedList *list = NULL;
	list = readfile(argv[1], list);

	if (list == NULL) {
		printf("Fatal error! file is not found\n");
		return 1;
	}

    char * md5_scheme = "$1$$";	 // type 1 implies md5 (number of iteration is only 1000 rounds)
    char * sha512_scheme = "$6$$";	 // type 2 implies sha-512 (default value as in yr 2017, number of iteration is minimum 10,000 rounds )
	char * md5_digest;
	char * sha512_digest;
	LinkedList *tmp = list;

	// Store hashes into linked list
	while (tmp->nextNode != NULL) {
		md5_digest = crypt(tmp->plaintext,md5_scheme); // MD5 Hash
		sha512_digest = crypt(tmp->plaintext,sha512_scheme); // SHA-512 Hash

		strcpy(tmp->md5, md5_digest);
		strcpy(tmp->sha512, sha512_digest);
		tmp = tmp->nextNode;
	}
	md5_digest = crypt(tmp->plaintext,md5_scheme); // MD5 Hash
	sha512_digest = crypt(tmp->plaintext,sha512_scheme); // SHA-512 Hash

	strcpy(tmp->md5, md5_digest);
	strcpy(tmp->sha512, sha512_digest);

	// print hashes
	printList(list);

	// Print execution time
	clock_t end = clock();
	double execTime = (double)(end - start) / CLOCKS_PER_SEC;
	printf("\nExecution time: %lf\n", execTime);
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
LinkedList *appendNode(char *plaintext, int length, LinkedList *head) {
	LinkedList *newNode = malloc(sizeof(LinkedList));
	// Allocate memory for hash
	newNode->md5 = malloc(MD5 * sizeof(char));
	newNode->sha512 = malloc(SHA512 * sizeof(char));
	newNode->plaintext = malloc(length * sizeof(char));
	strcpy(newNode->plaintext, plaintext);
	newNode->nextNode = NULL;

	if (head == NULL) {
		return newNode;
	} else {
		LinkedList *tmp = head;

		while (tmp->nextNode != NULL) {
			tmp = tmp->nextNode;
		}

		tmp->nextNode = newNode;

		return head;
	}
}

void printList(LinkedList *head) {
	LinkedList *tmp = head;

	while (tmp->nextNode != NULL) {
		printf("%s:%s\n", tmp->plaintext, tmp->md5);
		printf("%s:%s\n", tmp->plaintext, tmp->sha512);
		tmp = tmp->nextNode;
	}
	printf("%s:%s\n", tmp->plaintext, tmp->md5);
	printf("%s:%s\n", tmp->plaintext, tmp->sha512);
}

void writefile(char *name, char *content, unsigned long long size) {
	FILE *fp = fopen(name, "w");
	fwrite(content, 1, size, fp);
}

LinkedList *readfile(char *name, LinkedList *list) {
	// get file pointer
	FILE *fp = fopen(name, "r");
    char * line = NULL;
    size_t len = 0;
    int read;

    // check if file exists
	if (fp == NULL) {
		fclose(fp);
		return NULL;
	}

	// store each line into a linked list node
    while ((read = (int) getline(&line, &len, fp)) != -1) {
        line[strcspn(line,"\n")] = 0; // strip new line
        list = appendNode(line, read, list); // add new node to list
    }
    printf("\n");

	// close file
	fclose(fp);

	return list;
}
