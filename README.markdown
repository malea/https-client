# Network Programming Homework 5: Malea Grubb

## Compilation Instructions

    g++ grubbm_hw5.cpp -std=c++11 -lssl -lcrypto -g

Or:

    make

Use the included makefile.

## To Run

    ./a.out http://www.URLHERE:PORTHERE/PATHHERE/

or, for https:

    ./a.out https://www.URLHERE:PORTHERE/PATHHERE/

Note: if port left unspecified, it will be set to the default (80) for http, and default (443) for https
