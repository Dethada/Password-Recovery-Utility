#include <stdio.h>
#include <string.h>
#include <crypt.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <omp.h>

struct Hash {
	char *md5;
	char *sha512;
	char *plaintext;
};
typedef struct Hash Hash;

void printHelp(char *);
int isNotValid(char *);
void readfile(char *, Hash *, int, int);
int countLines(char *, int, int);
void writefile(char *, Hash *, int);
void is_valid_file(char *);

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
	is_valid_file(argv[1]);

	// print program start time
	time_t rawtime;
	struct tm * timeinfo;
	time (&rawtime);
	timeinfo = localtime (&rawtime);
	printf("Program started at: %s", asctime (timeinfo));

	int min = atoi(argv[2]);
	int max = atoi(argv[3]);
	int count = countLines(argv[1], min, max); // get number of lines
	Hash hashes[count];
	readfile(argv[1], hashes, min, max);
	printf("Total number of words processed => %d\n", count);

	int nProcessors = omp_get_max_threads(); // get number of threads avaliable
	omp_set_num_threads(nProcessors); // set number of threads to max avaliable
	#pragma omp parallel for
	for (int i = 0; i < count; i++) {
		hashes[i].md5 = strdup(crypt(hashes[i].plaintext, "$1$$")); // MD5 Hash
		hashes[i].sha512 = strdup(crypt(hashes[i].plaintext, "$6$$")); // SHA-512 Hash
	}

	writefile("hashes.txt", hashes, count); // write hashes out to disk

	printf("Total number of generated entries => %d\n", count << 1);

	// Print program end time
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "Program ended at: %s", asctime (timeinfo));
	return 0;
}

void is_valid_file(char *name) {
	FILE *fp = fopen(name, "r");
	// check if file exists
	if (fp == NULL) {
		printf("Fatal error! %s is not found\n", name);
		printf("Program halted. Please verify the file path and try again.\n");
		exit(EXIT_FAILURE);
	}
	fclose(fp);
}

void printHelp(char *name) {
	printf("Usage: %s <wordlist> <min> <max>\n\n", name);
	printf("\t<wordlist> : A file path/name in which contains the password dictonary\n");
	printf("\t<min> : An integer value greater than 1.\n\t\tThis value represents the minimum length of the password.\n");
	printf("\t<max> : An integer value greater than or equals to <min>.\n\t\t<max> represents the maximum length of the password\n");
}

/*
returns 1 when non-numeric character is detected
returns 0 when all characters are numeric
*/
int isNotValid(char *arg) {
	int i = 0;
	while (arg[i] != '\0') {
		if (!(isdigit(arg[i])))	return 1;
		i++;
	}
	return 0;
}

int countLines(char *name, int min, int max) {
	FILE *fp = fopen(name, "r");
	char * line = NULL;
	size_t len = 0;
	int lineLength;
	int count = 0;

	while ((lineLength = (int) getline(&line, &len, fp)) != -1) {
		if (lineLength < min || lineLength > max)	continue;
		count++;
	}

	return count;
}

void writefile(char *name, Hash *array, int len) {
	FILE *fp = fopen(name, "w");
	for (int i = 0; i < len; i++) {
		fprintf(fp, "%s:%s\n%s:%s\n", array[i].plaintext, array[i].md5, array[i].plaintext, array[i].sha512);
	}
	fclose(fp);
}

void readfile(char *name, Hash *array, int min, int max) {
	FILE *fp = fopen(name, "r");	// get file pointer
	char * line = NULL;
	size_t len = 0;
	int lineLength;
	int i = 0;

	// store each line into the array
	while ((lineLength = (int) getline(&line, &len, fp)) != -1) {
		if (lineLength < min || lineLength > max)	continue;
		line[strcspn(line,"\n")] = 0; // strip new line
		array[i].plaintext = strdup(line);
		i++;
	}

	free(line); // free memory
	fclose(fp); // close file
}
