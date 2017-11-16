#include <stdio.h>
#include <string.h>
#include <crypt.h>
/* source mkpassword.c
Author : Karl Kwan
Date: 6 Nov 2017
A demo program for ST2411.
Usage of crypt() to encrypt a simple plain text into a linux encrypted password.

To compile: need to include -lcrypt option.
e.g. cc -o mkpassword mkpassword.c -lcrypt

*/
int main(void)
{
/* 
		 
		To encrypt a text using crypt requires the following 3 components
			'The plain text' to be encrypted
			'hashing scheme'
			'salt'
			
 
*/
	char * plaintext = "ilovepython&c" ;
   
    char * hash_type_1 = "$1$";	 // type 1 implies md5 (number of iteration is only 1000 rounds)
    char * hash_type_2 = "$6$";	 // type 2 implies sha-512 (default value as in yr 2017, number of iteration is minimum 10,000 rounds )
	char * salt_1 ="$";			  // a simplified 0 length salt.
    char * salt_2 ="ABCD1234$";   // a normal 8 character salt.
	char * result;
	char encyption_scheme[20]; // 20 is more than enough.

	// prepare the first call using md5 and empty salt

	strcpy(encyption_scheme,hash_type_1);
	strcat(encyption_scheme,salt_1);
	result = crypt(plaintext,encyption_scheme);
	printf("The return from the 1st call of crypt() contains the md5 - HashID,Salt,encrypted String\n");
	printf("%s\n",result);
	// prepare the second call using sha-512 and a 8-char salt
	strcpy(encyption_scheme,hash_type_2);
	strcat(encyption_scheme,salt_2);
	result = crypt(plaintext,encyption_scheme);
	printf("The return from the 2nd call of crypt() contains the sha-512 HashID,Salt,encrypted String\n");
	printf("%s\n",result);
	 
}
