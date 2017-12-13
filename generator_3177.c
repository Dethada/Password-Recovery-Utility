/*
Author: David Zhu (P1703177)
Class: DISM/FT/1A/21
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <crypt.h>
#include <omp.h>
#include "functions_3177.h"

void printHelp(char *);
int isAllNumeric(char *);
void writefile(char *, Hash *, int);
void readfile(char *, Hash *, int, int);
unsigned long long countLines(char *, int, int);

int main(int argc, char *argv[]) {
	if (argc != 4) {
		printHelp(argv[0]);
		return 1;
	} else if (isAllNumeric(argv[2]) || isAllNumeric(argv[3])) {
		printHelp(argv[0]);
		return 1;
	} else if (atoi(argv[2]) > atoi(argv[3]) || atoi(argv[2]) < 1) {
		printHelp(argv[0]);
		return 1;
	}
	is_valid_file(argv[1]);

	/* print program start time */
	char buf[26];
	time_t rawtime;
	struct tm * timeinfo;
	time (&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(buf, 26, "%Y:%m:%d %H:%M:%S\n", timeinfo);
	printf("Program started at %s", buf);
	clock_t start = clock();

	int min = atoi(argv[2]);
	int max = atoi(argv[3]);
	unsigned long long count = countLines(argv[1], min, max); // get number of lines
	Hash hashes[count];
	readfile(argv[1], hashes, min, max);
	printf("Total number of words processed => %llu\n", count);

	int nProcessors = omp_get_max_threads(); // get number of threads avaliable
	omp_set_num_threads(nProcessors); // set number of threads to max avaliable
	#pragma omp parallel for
	for (int i = 0; i < count; i++) {
		/* https://stackoverflow.com/questions/9335777/crypt-r-example/9335810#9335810 */
		struct crypt_data data; // storage space for crypt_r
		data.initialized = 0;
		hashes[i].md5 = strdup(crypt_r(hashes[i].plaintext, "$1$$", &data)); // MD5 Hash
		hashes[i].sha512 = strdup(crypt_r(hashes[i].plaintext, "$6$$", &data)); // SHA-512 Hash
	}

	/* https://stackoverflow.com/questions/5248915/execution-time-of-c-program/5249150#5249150 */
	clock_t end = clock();
	double cpuTime = (double)(end - start) / CLOCKS_PER_SEC;

	writefile("mytab2411.txt", hashes, count); // write hashes out to disk
	printf("Total number of generated entries => %llu\n", count << 1);

	/* Print program end time */
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	/* https://stackoverflow.com/questions/3673226/how-to-print-time-in-format-2009-08-10-181754-811/3673291#3673291 */
	strftime(buf, 26, "%Y:%m:%d %H:%M:%S\n", timeinfo);
	printf("Program ended at %s", buf);
	printf("CPU time: %lf\n", cpuTime);
	return 0;
}

/* Prints out help menu 
takes program name as arg*/
void printHelp(char *name) {
	printf("Usage: %s <wordlist> <min> <max>\n\n", name);
	printf("\t<wordlist> : A file path/name in which contains the password dictonary\n");
	printf("\t<min> : An integer value greater than 0.\n\t\tThis value represents the minimum length of the password.\n");
	printf("\t<max> : An integer value greater than or equals to <min>.\n\t\t<max> represents the maximum length of the password\n");
}

/* takes an commandline arg as arg 
returns 1 when non-numeric character is detected
returns 0 when all characters are numeric */
int isAllNumeric(char *arg) {
	int i = 0;
	while (arg[i] != '\0') {
		if (!(isdigit(arg[i])))	return 1;
		i++;
	}
	return 0;
}

/* takes filename, min length and max length as args 
returns number of lines with length matching the min max in file */
unsigned long long countLines(char *name, int min, int max) {
	FILE *fp = fopen(name, "r");
	char * line = NULL;
	size_t len = 0;
	unsigned long long count = 0;

	/* https://stackoverflow.com/questions/3501338/c-read-file-line-by-line/3501681#3501681 */
	while ((getline(&line, &len, fp)) != -1) {
		/* https://stackoverflow.com/questions/2693776/removing-trailing-newline-character-from-fgets-input/28462221#28462221 */
		line[strcspn(line,"\n")] = 0; // strip new line
		int length = strlen(line);
		if (length < min || length > max)	continue;
		count++;
	}

	return count;
}

/* takes output filename, array of Hash structs and length of array as args
writes hashes out to disk */
void writefile(char *name, Hash *array, int len) {
	FILE *fp = fopen(name, "w");
	for (int i = 0; i < len; i++) {
		fprintf(fp, "%s:%s\n%s:%s\n", array[i].plaintext, array[i].md5, array[i].plaintext, array[i].sha512);
	}
	fclose(fp);
}

/* takes filename, array of Hash structs and min and max length as args
reads the wordlist into the array of Hash structs */
void readfile(char *name, Hash *array, int min, int max) {
	FILE *fp = fopen(name, "r");	// get file pointer
	char * line = NULL;
	size_t len = 0;
	int i = 0;

	/* https://stackoverflow.com/questions/3501338/c-read-file-line-by-line/3501681#3501681 */
	while ((getline(&line, &len, fp)) != -1) {
		/* https://stackoverflow.com/questions/2693776/removing-trailing-newline-character-from-fgets-input/28462221#28462221 */
		line[strcspn(line,"\n")] = 0; // strip new line
		int length = strlen(line);
		if (length < min || length > max)	continue;
		array[i].plaintext = strdup(line);
		i++;
	}

	free(line); // free memory
	fclose(fp); // close file
}