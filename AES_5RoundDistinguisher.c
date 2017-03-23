
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

word8 play[NUMBER_CP][16], cipher[NUMBER_CP][16], cipher2copy[NUMBER_CP][16];

word8 randomByte(){

    int a = genrand_int31();

    a = a % 16;

  return (word8) a;
}

word8 randomByte2(){

    return (word8) randomInRange(0,15);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

/**Merge-Sort Algorithm*/

/*given two ciphertexts a and b, it return 0 if a<=b, 1 otherwise */
int lessOrEqual(word8 a[], word8 b[], int coset)
{
    int i, temp, aaa, bbb;

    for(i=0;i<4;i++)
    {
        temp = 4*coset - 3 * i;

        if(temp < 0)
            temp = temp + 16;

        aaa = (int) a[temp];
        bbb = (int) b[temp];

        if(aaa>bbb)
            return 1;

        if(aaa<bbb)
            return 0;
    }

    return 0;
}

//int textEqual(word8 a[], word8 b[], int coset)
//{
//    int i, temp;
//
//    for(i=0;i<4;i++)
//    {
//        temp = 4*coset - 3 * i;
//
//        if(temp < 0)
//            temp = temp + 16;
//
//        if(((int) a[temp]) != ((int) b[temp]))
//            return 1;
//    }
//
//    return 0;
//}


double merging(int low, int mid, int high, int coset, double numberTableLook) {

    int l1, l2, i, j;
    word8 text1[16], text2[16];

    l1 = low;
    l2 = mid;

    for(j = 0; j<16; j++)
    {
        text1[j] = cipher[l1][j];
        text2[j] = cipher[l2][j];
    }

    numberTableLook = numberTableLook + 2.0;

    for(i = low; ((l1 < mid) && (l2 < high)); i++)
    {

        numberTableLook = numberTableLook + 1.0;

        if(lessOrEqual(text1, text2, coset) == 0)
        {
            for(j = 0; j<16; j++)
            {
                cipher2copy[i][j] = text1[j];
            }
            l1++;
            for(j = 0; j<16; j++)
            {
                text1[j] = cipher[l1][j];
            }

        }
        else
        {
            for(j = 0; j<16; j++)
            {
                cipher2copy[i][j] = text2[j];
            }
            l2++;
            for(j = 0; j<16; j++)
            {
                text2[j] = cipher[l2][j];
            }
        }
    }

    while(l1 < mid)
    {
        numberTableLook = numberTableLook + 1.0;

       for(j = 0; j<16; j++)
        {
            cipher2copy[i][j] = cipher[l1][j];
        }
        i++;
        l1++;
    }

    while(l2 < high)
    {
        numberTableLook = numberTableLook + 1.0;

       for(j = 0; j<16; j++)
        {
            cipher2copy[i][j] = cipher[l2][j];
        }
        i++;
        l2++;
    }

    for(i = low; i < high; i++)
    {
        numberTableLook = numberTableLook + 1.0;

        for(j = 0; j<16; j++)
        {
            cipher[i][j] = cipher2copy[i][j];
        }
    }

    return numberTableLook;
}

double merging2(int low, int mid, int high, int coset, double numberTableLook) {

    int l1, l2, i, j;
    word8 text1[16], text2[16];

    l1 = low;
    l2 = mid;

    for(j = 0; j<16; j++)
    {
        text1[j] = play[l1][j];
        text2[j] = play[l2][j];
    }

    numberTableLook = numberTableLook + 2.0;

    for(i = low; ((l1 < mid) && (l2 < high)); i++)
    {
        numberTableLook = numberTableLook + 1.0;

        if(lessOrEqual(text1, text2, coset) == 0)
        {
            for(j = 0; j<16; j++)
            {
                cipher2copy[i][j] = text1[j];
            }
            l1++;
            for(j = 0; j<16; j++)
            {
                text1[j] = play[l1][j];
            }
        }
        else
        {
            for(j = 0; j<16; j++)
            {
                cipher2copy[i][j] = text2[j];
            }
            l2++;
            for(j = 0; j<16; j++)
            {
                text2[j] = play[l2][j];
            }
        }
    }

    while(l1 < mid)
    {
       numberTableLook = numberTableLook + 1.0;

       for(j = 0; j<16; j++)
        {
            cipher2copy[i][j] = play[l1][j];
        }
        i++;
        l1++;
    }

    while(l2 < high)
    {
        numberTableLook = numberTableLook + 1.0;

       for(j = 0; j<16; j++)
        {
            cipher2copy[i][j] = play[l2][j];
        }
        i++;
        l2++;
    }

    for(i = low; i < high; i++)
    {
        numberTableLook = numberTableLook + 1.0;

        for(j = 0; j<16; j++)
        {
            play[i][j] = cipher2copy[i][j];
        }
    }

    return numberTableLook;
}

//void sort(int low, int high, int coset) {
//   int mid;
//
//   if(low < high) {
//
//      mid = (low + high) / 2;
//
//      sort(low, mid, coset);
//
//      sort(mid+1, high, coset);
//
//      merging(low, mid, high, coset);
//
//   }else {
//      return;
//   }
//}

double sort(int coset, double numberTableLook)
{
    int log, i, j, division, high, low, middle, a, b, c;
    word8 t1[16], t2[16];

    log = logarithm2(NUMBER_CP);

    for(i=0; i<NUMBER_CP; i = i+2)
    {
        numberTableLook = numberTableLook + 2.0;

        for(j=0;j<16;j++)
        {
            t1[j] = cipher[i][j];
            t2[j] = cipher[i+1][j];
        }

        if(lessOrEqual(t1, t2, coset) == 1)
        {
            for(j=0;j<16;j++)
            {
                cipher[i][j] = t2[j];
                cipher[i+1][j] = t1[j];
            }
            numberTableLook = numberTableLook + 2.0;
        }
    }

    for(i = 2; i < log; i++)
    {
        a = pow2(i);
        b = a/2;
        division = NUMBER_CP / a;

        for(j = 0; j < division; j++)
        {
            high = a * (j+1);
            low = a * j;
            middle = low + b;

            numberTableLook = merging(low, middle, high, coset, numberTableLook);

        }
    }

    return numberTableLook;

}

//void sort2(unsigned long int low, unsigned long int high, int coset) {
//   unsigned long int mid;
//
//   //printf("high: %d", high);
//
//   if(low < high) {
//
//      mid = (low + high) / 2;
//
//      sort2(low, mid, coset);
//
//      sort2(mid+1, high, coset);
//
//      merging2(low, mid, high, coset);
//
//   }else {
//      return;
//   }
//}

double sort2(int coset, double numberTableLook)
{
    int log, i, j, division, high, low, middle, a, b, c;
    word8 t1[16], t2[16];

    log = logarithm2(NUMBER_CP);

    for(i=0; i<NUMBER_CP; i = i+2)
    {
        for(j=0;j<16;j++)
        {
            t1[j] = play[i][j];
            t2[j] = play[i+1][j];
        }

        numberTableLook = numberTableLook + 2.0;

        if(lessOrEqual(t1, t2, coset) == 1)
        {
            for(j=0;j<16;j++)
            {
                play[i][j] = t2[j];
                play[i+1][j] = t1[j];
            }

            numberTableLook = numberTableLook + 2.0;
        }
    }

    for(i = 2; i < log; i++)
    {
        a = pow2(i);
        b = a/2;
        division = NUMBER_CP / a;

        for(j = 0; j < division; j++)
        {
            high = a * (j+1);
            low = a * j;
            middle = low + b;

            numberTableLook = merging2(low, middle, high, coset, numberTableLook);

        }
    }

    return numberTableLook;

}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**Count number of collision in the AES case! It must be an even number*/

unsigned long int subspaceTest(word8 key[][4])
{
    unsigned long int i, j, numero = 0;
    int l, k, indice1, indice2, indice3, indice4, coset, finalRes = 0, rTemp, flag = 0;

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

//    numero = 0;
//
//    //count number of collisions
//    for(i = 0; i < NUMBER_CP; i++)
//    {
//        for(j=i+1; j < NUMBER_CP; j++)
//        {
//
//            for(k = 0; k<4; k++)
//            {
//                for(l = 0; l<4; l++)
//                {
//                    p1[k][l] = play[i][k + l*4] ^ play[j][k + l*4];
//                }
//            }
//
//            numero = numero + (unsigned long int) belongToW_2(p1, 0);
//        }
//    }
//
//    printf("%d\n", numero);

    numero = 0;

    //Four times!

    for(coset = 0; coset < 4; coset++)
    {
        //re-order the ciphertexts!
        numberTableLook = sort2(coset, numberTableLook);

        //printf("Number of Look-ups: %f - Theoretical: ??? \n", numberTableLook);

        //count the number of collision
        i = 0;
        rTemp = 0;

        numero = 0;

        numberTableLook = numberTableLook + 1.0;

        while(i < (NUMBER_CP-1))
        {
            rTemp = 1;
            j = i;
            flag = 0;

            do
            {
                flag = 0;

                numberTableLook = numberTableLook + 1.0;

                for(k = 0; k<4; k++)
                {
                    for(l = 0; l<4; l++)
                    {
                        p1[k][l] = play[j+1][k + l*4] ^ play[j][k + l*4];
                    }
                }

                if(belongToW_2(p1, coset) == 1)
                {
                    rTemp = rTemp + 1;
                    flag = 1;
                    j = j + 1;
                }
            }while(flag == 1);

            i = j + 1;
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

    printf("Number of Look-ups: %.0f - Theoretical: 4456448 = 2^22 \n", numberTableLook);

    return finalRes;

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**Count number of collision in the random case!*/

unsigned long int randomTest(word8 key[][4])
{
    unsigned long int i, j, numero = 0;
    int l, k, flag, flag2, coset = 0, rTemp, finalNumber = 0, finalRes = 0, indice1, indice2, indice3, indice4;

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
        //re-order the ciphertexts!
        numberTableLook = sort(coset, numberTableLook);

        //count the number of collision
        i = 0;
        rTemp = 0;

        numero = 0;

        numberTableLook = numberTableLook + 1.0;

        while(i < (NUMBER_CP-1))
        {
            rTemp = 1;
            j = i;
            flag = 0;

            numberTableLook = numberTableLook + 1.0;

            do
            {
                flag = 0;

                for(k = 0; k<4; k++)
                {
                    for(l = 0; l<4; l++)
                    {
                        p1[k][l] = cipher[j+1][k + l*4] ^ cipher[j][k + l*4];
                        //numberTableLook = numberTableLook + 1.0;
                    }
                }

                if(belongToW_2(p1, coset) == 1)
                {
                    rTemp = rTemp + 1;
                    flag = 1;
                    j = j + 1;
                }
            }while(flag == 1);

            rTemp = rTemp * (rTemp - 1);
            i = j + 1;
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

//    numero = 0;
//
//    //count number of collisions
//    for(i = 0; i < NUMBER_CP; i++)
//    {
//        for(j=i+1; j < NUMBER_CP; j++)
//        {
//
//            for(k = 0; k<4; k++)
//            {
//                for(l = 0; l<4; l++)
//                {
//                    p1[k][l] = cipher[i][k + l*4] ^ cipher[j][k + l*4];
//                }
//            }
//
//            numero = numero + (unsigned long int) belongToW_2(p1, 0);
//        }
//    }
//
//    printf("%d\n", numero);



    printf("Number of Look-ups: %.0f - Theoretical: 4456448 = 2^22 \n", numberTableLook);

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
    //srand (time(NULL));

    printf("AES case:\n");

    for(i=0; i < NUMBER_TEST; i++)
    {
        //create a random key;
        for(k=0;k<4;k++)
        {
            for(j=0;j<4;j++)
                key[j][k] = (word8) randomInRange(0, 15);
        }

        printf("Number Test: %d\n", i+1);

        /*if((i%1) == 0)
        {
            printf("%lu - %lu - %lu - %lu - %lu\n", i, numero, numero2, nn, nn2);
        }*/

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
                key[j][k] =  randomInRange(0, 15);
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
