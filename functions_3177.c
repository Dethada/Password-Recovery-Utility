/*
Author: David Zhu (P1703177)
Class: DISM/FT/1A/21
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "functions_3177.h"

/* takes in a file name as arg
exits the program if file name is invalid */
void is_valid_file(char *name) {
	FILE *fp = fopen(name, "r");
	/* check if file exists */
	if (fp == NULL) {
		printf("Fatal error! %s is not found\n", name);
		printf("Program halted. Please verify the file path and try again.\n");
		exit(EXIT_FAILURE);
	}
	/* longest file path is 4096
	from: https://unix.stackexchange.com/questions/32795/what-is-the-maximum-allowed-filename-and-folder-size-with-ecryptfs */
	if (strlen(name) > 4096) {
		printf("Fatal error! File name is too long\n");
		printf("Program halted.\n");
		exit(EXIT_FAILURE);
	}
	/* 4096+strlen("/usr/bin/file ")+1 = 4111 */
	char cmd[4111];
	char result[255];
	strcpy(cmd, "/usr/bin/file ");
	strcat(cmd, name);
	FILE *pipe = popen(cmd, "r"); // use file command to check if file is ascii text file
	if (pipe == NULL) { // if the command fails
		if (strcasestr(name, ".txt") == NULL) {
			printf("Program halted. Please ensure the input file is a txt file\n");
			exit(EXIT_FAILURE);
		}
		return;
	}

	fgets(result, sizeof(result)-1, pipe);
	if (result[0] == 0x0) {
		printf("Please ensure you have the file command installed.\n");
		if (strcasestr(name, ".txt") == NULL) {
			printf("Program halted. Please ensure the input file is a txt file\n");
			exit(EXIT_FAILURE);
		}
	} else if (strstr(result, "ASCII text") == NULL) {
		printf("Fatal error! %s is not a text file!\n", name);
		printf("Program halted. Please use a textfile and try again.\n");
		exit(EXIT_FAILURE);
	}

	/* close */
	pclose(pipe);
	fclose(fp);
}