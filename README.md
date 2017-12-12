# C Assignment

Remember to link crypt library and openmp using `-lcrypt` and `-fopenmp` when compiling.

## General To-dos

* At the beginning of each function, add in comments, to state clearly of the purpose of the function, the input parameter(s) (if any), and the return value (if any).
* Report
* Add screen shots of testing

## Cryptographic hash lookup generator
![](images/task1.png) 
> Execution Time using 8 threads: 48s (wordlist.txt)

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
