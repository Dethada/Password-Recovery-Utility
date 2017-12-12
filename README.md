# C Assignment

Remember to link crypt library and openmp using `-lcrypt` and `-fopenmp` when compiling.

# General To-dos

* Use a header file for common functions
* format time according to requirement
* breakdown large functions into sub functions

## Cryptographic hash lookup generator
![](images/task1.png) 
> Execution Time using 8 threads: 48s (wordlist.txt)

* Improve readability
* ~~Change default output filename to  'mytab2411.txt'~~
* ~~Use threadsafe version of crypt (crypt_r)~~
* ~~Add multithreading~~
* ~~Use file command to validate input file is a text file~~
* ~~if system do not have file command check for txt extension~~

##  Password Recovery Utility
![](images/task2.png) 
> Runtime: less than 1 second

* ~~Parse data into username and password~~
* ~~Display invalid entries~~
* ~~Improve efficiency by only check for the correct hashing algorithm~~
