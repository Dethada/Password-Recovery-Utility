#include <stdio.h>
#include <string.h>
#include <crypt.h>
#include <stdlib.h>
#include <time.h>
#define MD5 26
#define SHA512 90

struct LinkedList
{
	char *hash;
	char *plaintext;
	struct LinkedList *nextNode;
};
typedef struct LinkedList LinkedList;

LinkedList *createNode(char *, char *, int, int);
LinkedList *appendNode(char *, char *, int, int, LinkedList *);
void printList(LinkedList *);
void readfile(char *);

int main(void)
{
	clock_t start = clock();
	LinkedList *md5List = NULL;
	LinkedList *sha512List = NULL;

	readfile("small_wordlist.txt");

	char * plaintext[] = {"ilovepython&c", "abc", "edasdf"} ;
    char * encyption_scheme1 = "$1$$";	 // type 1 implies md5 (number of iteration is only 1000 rounds)
    char * encyption_scheme2 = "$6$$";	 // type 2 implies sha-512 (default value as in yr 2017, number of iteration is minimum 10,000 rounds )
	char * result;

	// Store hashes into linked list
	for (int i=0; i < 3; i++) {
		result = crypt(plaintext[i],encyption_scheme1); // MD5 Hash
		md5List = appendNode(result, plaintext[i], strlen(plaintext[i]), MD5, md5List);

		result = crypt(plaintext[i],encyption_scheme2); // SHA-512 Hash
		sha512List = appendNode(result, plaintext[i], strlen(plaintext[i]), SHA512, sha512List);
	}

	// print hashes
	printList(md5List);
	printf("\n\n");
	printList(sha512List);

	// Print execution time
	clock_t end = clock();
	double execTime = (double)(end - start) / CLOCKS_PER_SEC;
	printf("\nExecution time: %lf\n", execTime);
}

LinkedList *createNode(char * hash, char *plaintext, int length, int size) {

	LinkedList *newNode = malloc(sizeof(LinkedList));
	newNode->hash = malloc(size * sizeof(char));
	strcpy(newNode->hash, hash);
	newNode->plaintext = malloc(length * sizeof(char));
	strcpy(newNode->plaintext, plaintext);
	newNode->nextNode = NULL;

	return newNode;
}

LinkedList *appendNode(char *hash, char *plaintext, int length, int size, LinkedList *head) {
	LinkedList *newNode = malloc(sizeof(LinkedList));
	newNode->hash = malloc(size * sizeof(char));
	strcpy(newNode->hash, hash);
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
		printf("%s:%s\n", tmp->plaintext, tmp->hash);
		tmp = tmp->nextNode;
	}
	printf("%s:%s\n", tmp->plaintext, tmp->hash);
}


void readfile(char *name) {
	// get file pointer
	FILE *fp = fopen(name, "r");
    char * line = NULL;
    size_t len = 0;
    int read;

	if (fp == NULL) {
		printf("Fatal error! %s is not found\n", name);
		fclose(fp);
		return;
	}

	// store each line into a linked list node
    while ((read = (int) getline(&line, &len, fp)) != -1) {
        printf("Retrieved line of length %d :\n", read);
        printf("%s", line);
    }
    printf("\n");

	// close file
	fclose(fp);
}
