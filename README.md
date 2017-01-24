# AES_5round_SKdistinguisher

Secret-Key Distinguisher for 5-round of AES.

We refer to "A New Structural-Differential Property of 5-Round AES" of L. Grassi, C. Rechberger and S. Ronjom (see https://eprint.iacr.org/) for a complete description. We limit here to briefly describe the implementations.

Programs:

0) AES_smallScaleVersion.c

1) AES_5Round_Distinguisher.c

The programs should run with almost C-compilers (we have used gcc version 4.8.1). None of these programs is speed-optimized, they are for verification purposes only.

In all the programs, the main function is always the last one.

The first program contains our implementation of small scale version of AES (encryption and decryption), that is AES with words of 4 bits instead of 8. 
A complete description of it can be found in "Small Scale Variants of the AES", C. Cid et al. - http://link.springer.com/chapter/10.1007%2F11502760_10 
It has been verified against test-vectors.

The other one is the secret-key distinguisher on 5-rounds of AES.

For each program, the user can choose the secret key (which is defined in the main fuction). 

In the following, we give a detailed description of the secret key-distinguisher.

The program generates plaintexts in the same coset of D_i, and the corresponding ciphertexts.

For the random case, two possibiltiy are available in order to set up a random permutation:
- true random permutation (using "rand");
- 25 rounds of AES.
The second one is much faster than the first one (since it requires a less number of rand()), and its behave is similar to the random one.

It is possible to choose the two possibilies using "RANDOM_GENERATION" at line 8 (note: 0 for 25-rounds AES, 1 for random).

Then, the programs counts the number of collisions among the ciphertexts in the same coset of M_J, for each possible J, that is
- J = 0, 1, 2
- J = 0, 1, 3
- J = 0, 2, 3
- J = 1, 2, 3

It prints this number n and the corresponding n % 2.
We expect that for AES all the numbers are even, while we expect that at least one of these numbers is odd number in the random case with probability higher than 95% if more than 2 initial cosets of D_i are used (for a total of 2^33 tests).

The number of cosets of D_i used (i.e. number of different cosets used) is defined by "NUMBER_TEST" at line 7 (it is equal to 2 by default).
Note: DON'T MODIFY "NUMBER_CP" and "N_Round".

The program prints also the computational cost, which can be compared with the theoretical one.

Average Time of Execution: 3 sec (setting: NUMBER_TEST=2 and RANDOM_GENERATION = 0).

Finally, the Random Generator used in this code is the "Mersenne Twister" one, developed by 1997 by Makoto Matsumoto
and Takuji Nishimura - MT19937, and that can be found in http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c
