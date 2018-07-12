# AES_5round_SKdistinguisher

Secret-Key Distinguisher for 5-round of AES.

We refer to "A New Structural-Differential Property of 5-Round AES" of L. Grassi, C. Rechberger and S. Ronjom (see https://eprint.iacr.org/2017/118) for a complete description. We limit here to briefly describe the implementations.

0) AES_smallScaleVersion.c

1) AES_5Round_Distinguisher.c

2) AES_5Round_Distinguisher_hashTable.c

3) AESmultiple-of-8.ccp

The programs should run with almost C-compilers (we have used gcc version 4.8.1). None of these programs is speed-optimized, they are for verification purposes only.

In all the programs, the main function is always the last one.

--(0)-- The first program contains our implementation of small scale version of AES (encryption and decryption), that is AES with words of 4 bits instead of 8. 
A complete description of it can be found in "Small Scale Variants of the AES", C. Cid et al. - http://link.springer.com/chapter/10.1007%2F11502760_10 
It has been verified against test-vectors.

--(1-2)-- The other two are the secret-key distinguishers on 5-round (small-scale) AES:
1) "AES_5Round_Distinguisher.c" uses a re-ordering algorithm to implement the distinguisher;
2) "AES_5Round_Distinguisher_hashTable.c" uses hash-table/array to implement the distinguisher.
A complete description of the distinguisher and of the implementations can be found in the paper.

For each program, the user can choose the secret key (which is defined in the main fuction). 

In the following, we give a detailed description of the secret-key distinguisher.

The program generates plaintexts in the same coset of D_i, and the corresponding ciphertexts.

For the random case, two possibilties are available in order to set up a random permutation:
- true random permutation (using "rand");
- 25 rounds of AES.
The second one is much faster than the first one (since it requires a less number of rand()), and its behave is similar to the random one.

It is possible to choose the two possibilies using "RANDOM_GENERATION" at line 8 (note: 0 for 25-rounds AES, 1 for random).

Given plaintexts in the same coset of D_i, the programs counts the number of collisions among the ciphertexts in the same coset of M_J, for each possible J, that is
- J = 0, 1, 2
- J = 0, 1, 3
- J = 0, 2, 3
- J = 1, 2, 3

It prints this number n and the corresponding n % 8.
We expect that for AES all the numbers n are even, while we expect that at least one of these numbers is odd number in the random case with probability higher than 99% if more than a single initial coset of D_i is used (for a total of 2^32 tests).

The number of cosets of D_i used (i.e. number of different cosets used) is defined by "NUMBER_TEST" at line 7 (it is equal to 1 by default).
Note: DON'T MODIFY "NUMBER_CP" and "N_Round".

The programs print also the computational cost, which can be compared with the theoretical one.

Average Time of Execution:
1) "AES_5Round_Distinguisher.c": < 1 sec (setting: NUMBER_TEST=1 and RANDOM_GENERATION = 0);
2) "AES_5Round_Distinguisher_hashTable.c": < 0.5 sec (setting: NUMBER_TEST=1 and RANDOM_GENERATION = 0).

Tthe Random Generator used in this code is the "Mersenne Twister" one, developed by 1997 by Makoto Matsumoto
and Takuji Nishimura - MT19937, and that can be found in http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c

--(3)-- The last one is the distinguisher implemented for real (full-scale) AES. It works as the ones just described. 
The flags to compile the code on unix machines is:

g++ -o <name> -g -O0 -Wall -msse2 -msse -march=native -maes -lpthread main.cpp

