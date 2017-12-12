/*
Author: David Zhu (P1703177)
Class: DISM/FT/1A/21
*/
#ifndef FUNCTIONS_H
#define FUNCTIONS_H

struct Hash {
	char *md5;
	char *sha512;
	char *plaintext;
};
typedef struct Hash Hash;

void is_valid_file(char *);

#endif // FUNCTIONS_H