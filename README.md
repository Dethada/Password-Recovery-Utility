# C Assignment

Remember to link crypt library using `-lcrypt` when compiling.

## Cryptographic hash lookup generator

> Execution Time using 8 threads: 48s (wordlist.txt)

* Add option to choose number of threads to use
* Use unsigned long long for count variable
* Improve readability
* Check if input file is a text file (check for .txt extension)

##  Password Recovery Utility

> Runtime: 804s

* Parse data into username:password ignore the rest for now
* Check if the format of the file is valid while parsing
* Display invalid entries
* Check if the password hash in shadow file is present in the lookup table generated
* Improve efficiency by only check for the correct hashing algorithm

