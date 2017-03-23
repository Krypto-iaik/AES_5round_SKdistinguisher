
/**The Random Generator used in this code is the "Mersenne Twister" one, developed by 1997 by Makoto Matsumoto
and Takuji Nishimura - MT19937.
The complete source code of the random generator can be found in http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c
We also attach the following:
"A C-program for MT19937, with initialization improved 2002/1/26.
   Coded by Takuji Nishimura and Makoto Matsumoto.
   Before using, initialize the state by using init_genrand(seed)
   or init_by_array(init_key, key_length).
   Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
   All rights reserved.
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
     1. Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.
     2. Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
     3. The names of its contributors may not be used to endorse or promote
        products derived from this software without specific prior written
        permission.
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   Any feedback is very welcome.
   http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
   email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)"
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "AES_common.h"
#include "AES_smallScale_sbox.h"
#include "multiplication.h"
#include "subspace_checks.h"

#define NUMBER_CP 65536
/**PLEASE: DON'T MODIFY THE PREVIOUS TWO NUMBERS!*/
#define NUMBER_TEST 1
#define RANDOM_GENERATION 0
/**0: in the random case, the ciphertexts are generated as 25 AES encryption; 1: in a random way.
NOTE: 0 is much much faster than 1!*/

word8 play[NUMBER_CP][16], cipher[NUMBER_CP][16];
int arrray[65536];

word8 randomByte(){

    int a = genrand_int31();

    a = a % 16;

  return (word8) a;
}

word8 randomByte2(){

    return (word8) randomInRange(0,15);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

long int pow(int r, int e)
{
    int i;
    long int result = 1;

    if(e == 0)
        return 1;

    if(e < 0)
        return -1;

    for(i = 0; i<e; i++)
    {
        result = result * r;
    }

    return result;
}

int logarithm2(long int n)
{
    long int i = 1;
    int j = 1;

    if (n<=0)
        return -1;

    if (n == 1)
        return 0;

    while(i<n)
    {
        i = i * 2;
        j++;
    }

    return j;

}

long int pow2(int n)
{
    long int i = 1;
    int j;

    if(n == 0)
        return 1;

    for(j=0; j<n;j++)
    {
        i = i * 2;
    }

    return i;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**Count number of collision in the AES case! It must be an even number*/

unsigned long int subspaceTest(word8 key[][4])
{
    unsigned long int i, j, numero = 0;
    int l, k, indice1, indice2, indice3, indice4, coset, finalRes = 0, flag = 0, boh, rTemp;

    double numberTableLook = 0.0;

    word8 p1[4][4], c1[4][4], temp[4][4];

    for(k=0;k<4;k++)
    {
        for(l=0;l<4;l++)
            temp[l][k]=randomByte();
    }

    i = 0;

    for(indice1 =0; indice1<16; indice1++)
    {
        for(indice2=0; indice2 <16; indice2++)
        {
            for(indice3=0; indice3<16; indice3++)
            {
                for(indice4=0; indice4<16; indice4++)
                {
                    temp[0][0] = (word8) indice1;
                    temp[1][1] = (word8) indice2;
                    temp[2][2] = (word8) indice3;
                    temp[3][3] = (word8) indice4;

                    encryption(temp, key, &(c1[0][0]));

                    //i = (long int) indice4 + (long int) (indice3 * 16) + (long int) (indice2 * 256) + (long int) (indice1 * 4096);

                    for(k = 0; k<4; k++)
                    {
                        for(l=0;l<4;l++)
                            play[i][k + l*4] = c1[k][l];
                    }

                    i++;

                }
            }
        }
    }

    //Four times!

    for(coset = 0; coset < 4; coset++)
    {
        for(i = 0; i<65536; i++)
        {
            arrray[i] = 0;
        }

        for(i = 0; i<NUMBER_CP; i++)
        {
            numero = 0;
            numberTableLook++;

            for(j = 0; j<4; j++)
            {
                boh = coset - j;
                if(boh < 0)
                    boh = boh + 4;

                numero = numero + pow(16, j) * play[i][j + 4 * boh];
            }

            arrray[numero]++;
            numberTableLook++;
        }

        numero = 0;

        for(i = 0; i<65536; i++)
        {
            rTemp = arrray[i];
            numberTableLook++;
            rTemp = rTemp * (rTemp - 1);
            numero = numero + (rTemp/ 2);
        }

        printf("M_");
        for(j=0;j<4;j++)
        {
            if(j!= coset)
            {
                printf("%d", j);
                if(((j<3)&&(coset!=3))||((j<2)&&(coset==3)))
                    printf(",");
            }
        }
        printf(" - %d - %d\n", numero, (numero%8));

        if((numero%8) != 0)
        {
            printf("\t NOTE: Something Wrong!\n");
            finalRes = 1;
        }

    }

    printf("Number of Look-ups: %.0f - Theoretical: 786432 = 2^19.6 \n", numberTableLook);

    return finalRes;

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**Count number of collision in the random case!*/

unsigned long int randomTest(word8 key[][4])
{
    unsigned long int i, j, numero = 0;
    int l, k, flag, flag2, coset = 0, rTemp, finalNumber = 0, finalRes = 0, indice1, indice2, indice3, indice4, boh;

    word8 p1[4][4], c1[4][4], temp[4][4], temp2[4][4];

    double numberTableLook = 0.0;

    /**The ciphertexts are generated in a random way*/
    if(RANDOM_GENERATION == 1)
    {
        for(i=0; i<NUMBER_CP; i++)
        {
            do
            {
                flag2 = 0;

                for(k=0;k<4;k++)
                {
                    for(l=0;l<4;l++)
                        temp[l][k]=randomByte();
                }

                for(j=0;((j<i)&&(i>0));j++)
                {
                    flag = 0;
                    for(k=0;k<4;k++)
                    {
                        for(l=0;l<4;l++)
                        {
                            if(temp[l][k]==cipher[j][l+4*k])
                                flag++;
                        }
                    }

                    if(flag == 16)
                        flag2 = 1;

                }

                if(flag2 == 0)
                {
                    for(k=0;k<4;k++)
                    {
                        for(l=0;l<4;l++)
                        {
                            cipher[i][l+4*k] = temp[l][k];
                        }
                    }
                }
            }while(flag2 == 1);

            /*encryption(temp, key, &(c1[0][0]));

            for(k = 0; k<4; k++)
            {
                for(l=0;l<4;l++)
                    play[i][k + l*4] = c1[k][l];
            }*/
        }
    }
    /**The ciphertexts are generated by the plaintexts, as 25 encryption of AES -> IT IS MUCH MUCH FASTER!!!*/
    else
    {
        for(k=0;k<4;k++)
        {
            for(l=0;l<4;l++)
                temp[l][k]=randomByte();
        }

        i = 0;

        for(indice1 =0; indice1<16; indice1++)
        {
            for(indice2=0; indice2 <16; indice2++)
            {
                for(indice3=0; indice3<16; indice3++)
                {
                    for(indice4=0; indice4<16; indice4++)
                    {
                        temp[0][0] = (word8) indice1;
                        temp[1][1] = (word8) indice2;
                        temp[2][2] = (word8) indice3;
                        temp[3][3] = (word8) indice4;

                        encryption(temp, key, &(c1[0][0]));
                        encryption(c1, key, &(temp2[0][0]));
                        encryption(temp2, key, &(c1[0][0]));
                        encryption(c1, key, &(temp2[0][0]));
                        encryption(temp2, key, &(c1[0][0]));

                        //i = (long int) indice4 + (long int) (indice3 * 16) + (long int) (indice2 * 256) + (long int) (indice1 * 4096);

                        for(k = 0; k<4; k++)
                        {
                            for(l=0;l<4;l++)
                                cipher[i][k + l*4] = c1[k][l];
                        }

                        i++;

                    }
                }
            }
        }
    }

    //Four times!

    for(coset = 0; coset < 4; coset++)
    {
        for(i = 0; i<65536; i++)
        {
            arrray[i] = 0;
        }

        for(i = 0; i<NUMBER_CP; i++)
        {
            numero = 0;

            numberTableLook++;

            for(j = 0; j<4; j++)
            {
                boh = coset - j;
                if(boh < 0)
                    boh = boh + 4;

                numero = numero + pow(16, j) * cipher[i][j + 4 * boh];
            }

            arrray[numero]++;
            numberTableLook++;
        }

        numero = 0;

        for(i = 0; i<65536; i++)
        {
            rTemp = arrray[i];
            numberTableLook++;
            rTemp = rTemp * (rTemp - 1);
            numero = numero + (rTemp/ 2);
        }
        printf("M_");
        for(j=0;j<4;j++)
        {
            if(j!= coset)
            {
                printf("%d", j);
                if(((j<3)&&(coset!=3))||((j<2)&&(coset==3)))
                    printf(",");
            }
        }
        printf(" - %d - %d\n", numero, (numero%8));

        if((numero%8) != 0)
        {
            printf("\t NOTE: Random Permutation!\n");
            finalRes = 1;
        }

    }

    printf("Number of Look-ups: %.0f - Theoretical: 786432 = 2^19.6 \n", numberTableLook);

    return finalRes;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**AES Secret Key Distinguisher.

Idea: given a coset of D, the number of collisions after 5 rounds in the same coset of M is a multiple of 8 - dim(M) = 12,
while no property holds for the random case.*/

int main()
{
    word8 key[4][4] = {
        0x5, 0x3, 0x4, 0xc,
        0xd, 0x0, 0xa, 0xd,
        0x2, 0xf, 0xe, 0x3,
        0xf, 0x7, 0x9, 0x1
    };

    int l, k, flag = 0;

    unsigned long int i, numero = 0, numero2 = 0, j, nn=0, nn2=0;

    srand (time(NULL));

    unsigned long init[4], length=4;

    //check that we're working with 4 bits!
    for(k=0;k<4;k++)
    {

        for(j=0;j<4;j++)
            key[j][k] =  key[j][k] & 0x0f;
    }

    for(k=0;k<length;k++)
    {
        init[k] = rand();
    }
    init_by_array(init, length);

    printf("Secret Key Distinguisher 5 rounds of AES.\n\n");
    printf("For each of the %d tests, the program generates texts and counts the total number of collisions both in the random and in the subspace case.\n\n", NUMBER_TEST);

    printf("It prints the following things:\n");
    printf("Subspace of M -\nNumber of Collisions -\nCollision % 8\n\n");

    //initialize seed
    //srand(time(NULL));

    printf("AES case:\n");

    for(i=0; i < NUMBER_TEST; i++)
    {
        printf("Number Test: %d\n", i+1);

        //create a random key;
        for(k=0;k<4;k++)
        {
            for(j=0;j<4;j++)
                key[j][k] = (word8) randomInRange(0, 15);
        }

        for(j=0;j<NUMBER_CP; j++)
        {
            for(l=0;l<16; l++)
            {
                play[j][l] = 0;
                cipher[j][l] = 0;
            }
        }

         nn2 = subspaceTest(key);

         if(nn2 == 1)
         {
             printf("Something Wrong...\n");
             flag = 1;
             return 1;
         }
    }

    printf("\nRANDOM case:\n");

    for(i=0; i < NUMBER_TEST; i++)
    {

        //create a random key;
        for(k=0;k<4;k++)
        {
            for(j=0;j<4;j++)
                key[j][k] = (word8) randomInRange(0, 15);
        }

        printf("Number Test: %d\n", i+1);

        for(j=0;j<NUMBER_CP; j++)
        {
            for(l=0;l<16; l++)
            {
                play[j][l] = 0;
                cipher[j][l] = 0;
            }
        }

         nn = randomTest(key);

         if(nn == 1)
         {
             flag = 1;
         }

         printf("\n");

    }

    printf("\nCONCLUSION:\n");
    if(flag == 1)
    {
        printf("The distinguisher works!\n");
    }
    else
    {
        printf("It is not possible to distinguish the two cases: use more tests!\n");
    }

    /*printf("Total collision in the random case: %lu - Modulo 8: %lu\n", numero, numero%8);
    printf("Total collision in the AES case: %lu - Modulo 8: %lu\n", numero2, numero2%8);*/

    return (0);
}
