# C Assignment

Remember to link crypt library using `-lcrypt` when compiling.

## Cryptographic hash lookup generator

> Read Time: 118s
>
> MD5 Hash Time: 117s
>
> SHA512 Hash Time: 237s
>
> Execution Time: 238s (wordlist.txt)

* Increase efficiency
* Improve readability
* Check if input file is a text file

##  Password Recovery Utility

> Runtime: 804s

* Parse data into username:password ignore the rest for now
* Check if the format of the file is valid while parsing
* Display invalid entries
* Check if the password hash in shadow file is present in the lookup table generated
* Improve efficiency by only check for the correct hashing algorithm