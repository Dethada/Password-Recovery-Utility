#include <stdio.h>
#include <string.h>
#include <crypt.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#define MD5 26
#define SHA512 90

struct LinkedList {
	char *md5;
	char *sha512;
	char *plaintext;
	struct LinkedList *nextNode;
};

struct fileContent {
	char *name;
	int min;
	int max;
	struct LinkedList *list;
};

typedef struct LinkedList LinkedList;
typedef struct fileContent fileContent;

LinkedList *createNode(char *, int);
void appendNode(char *, int, LinkedList *);
void writefile(char *, LinkedList *);
void printHelp(char *);
int isNotValid(char *);

// Threaded functions
void *readfile(void *);
void *hashMD5(void *);
void *hashSHA512(void *);

int readDone = 0;	// Set to 1 when the whole filed is loaded into memory

int main(int argc, char *argv[]) {
	if (argc != 4) {
		printHelp(argv[0]);
		return 1;
	} else if (isNotValid(argv[2]) || isNotValid(argv[3])) {
		printHelp(argv[0]);
		return 1;
	} else if (atoi(argv[2]) > atoi(argv[3])) {
		printHelp(argv[0]);
		return 1;
	}
	pthread_t read_thread, md5_thread, sha512_thread;
	int  ret1, ret2, ret3;

	time_t rawtime;
	struct tm * timeinfo;

	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "Program started at: %s", asctime (timeinfo) );
	LinkedList *list = createNode("start", 5) ; // create a starting node
	fileContent *contents = malloc(sizeof(fileContent));
	contents->name = argv[1];
	contents->min = atoi(argv[2]);
	contents->max = atoi(argv[3]);
	contents->list = list;

	// hash words
	ret1 = pthread_create( &read_thread, NULL, readfile, (void*)contents);
	if(ret1) {
		fprintf(stderr,"Error - pthread_create() return code: %d\n",ret1);
		exit(EXIT_FAILURE);
	}
	ret2 = pthread_create( &md5_thread, NULL, hashMD5, (void*)list);
	if(ret2) {
		fprintf(stderr,"Error - pthread_create() return code: %d\n",ret2);
		exit(EXIT_FAILURE);
	}
	ret3 = pthread_create( &sha512_thread, NULL, hashSHA512, (void*)list);
	if(ret3) {
		fprintf(stderr,"Error - pthread_create() return code: %d\n",ret3);
		exit(EXIT_FAILURE);
	}
	pthread_join( read_thread, NULL);
	pthread_join( md5_thread, NULL);
	pthread_join( sha512_thread, NULL);

	// write hashes to file
	writefile("hashes.txt", list);

	// Print time
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "Program ended at: %s", asctime (timeinfo) );
}

// returns 1 when invalid, 0 when valid
int isNotValid(char *arg) {
	int i = 0;
	while (arg[i] != '\0') {
		if (!(isdigit(arg[i]))) {
			return 1;
		}
		i++;
	}
	return 0;
}

void printHelp(char *name) {
	printf("Usage: %s <wordlist> <min> <max>\n\n", name);
	printf("\t<wordlist> : A file path/name in which contains the password dictonary\n");
	printf("\t<min> : An integer value greater than 1.\n\t\tThis value represents the minimum length of the password.\n");
	printf("\t<max> : An integer value greater than or equals to <min>.\n\t\t<max> represents the maximum length of the password\n");
}

void waitFor(unsigned int secs) {
	unsigned int retTime = time(0) + secs;   // Get finishing time.
	while (time(0) < retTime);               // Loop until it arrives.
}

// can combine with sha512
void *hashMD5(void *voidptr) {
	waitFor(1);
	LinkedList *list = (LinkedList*)voidptr;
	char *md5_scheme = "$1$$";	 // type 1 implies md5 (number of iteration is only 1000 rounds)
	LinkedList *tmp = list->nextNode;

	time_t start = time(NULL);
	// Store hashes into linked list
	while (readDone != 1 || tmp->nextNode != NULL) {
		if (tmp->nextNode == NULL) {
			continue;
		}
		strcpy(tmp->md5, crypt(tmp->plaintext,md5_scheme)); // MD5 Hash
		tmp = tmp->nextNode;
	}
	strcpy(tmp->md5, crypt(tmp->plaintext,md5_scheme)); // MD5 Hash
	printf("\nMD5 Hash Time: %f\n", (double)(time(NULL) - start));
}

// can combine with md5
void *hashSHA512(void *voidptr) {
	waitFor(1);
	LinkedList *list = (LinkedList*)voidptr;
	char *sha512_scheme = "$6$$";	 // type 2 implies sha-512 (default value as in yr 2017, number of iteration is minimum 10,000 rounds )
	LinkedList *tmp = list;

	time_t start = time(NULL);
	// Store hashes into linked list
	for (tmp = list->nextNode; tmp->nextNode != NULL; tmp = tmp->nextNode) {
		strcpy(tmp->sha512, crypt(tmp->plaintext,sha512_scheme)); // SHA-512 Hash
	}
	strcpy(tmp->sha512, crypt(tmp->plaintext,sha512_scheme)); // SHA-512 Hash
	printf("\nSHA512 Hash Time: %f\n", (double)(time(NULL) - start));
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

// Reads each line of the file into a linked list
void *readfile(void *voidPtr) {
	time_t start = time(NULL);
	fileContent *content = (fileContent*)voidPtr;
	FILE *fp = fopen(content->name, "r");	// get file pointer
	char * line = NULL;
	size_t len = 0;
	int lineLength;
	unsigned long long count = 0; // number of lines/words

	// check if file exists
	if (fp == NULL) {
		printf("Fatal error! %s is not found\n", content->name);
		printf("Program halted. Please verify the file path and try again.\n");
		exit(EXIT_FAILURE);
	}
	
	// store each line into a linked list node
	while ((lineLength = (int) getline(&line, &len, fp)) != -1) {
		if (lineLength < content->min || lineLength > content->max) {
			continue;
		}
		line[strcspn(line,"\n")] = 0; // strip new line
		appendNode(line, lineLength, content->list); // add new node to list
		count++;
	}
	printf("Total number of words processed => %llu\n", count);
	printf("Total number of generated entries => %llu\n", count * 2);
	readDone = 1;
	free(line);
	// close file
	fclose(fp);
	printf("\nRead Time: %f\n", (double)(time(NULL) - start));
}
