CFLAGS=-O3 -Wall

all: AES_smallScale AES_5RoundDistinguisher AES_5RoundDistinguisher_hashTable

multiplication: multiplication.h multiplication_smallScale.c
	$(CC) $(CFLAGS) -c -o multiplication_smallScale.o multiplication_smallScale.c
	
subspace_checks: subspace_checks.h subspace_checks.c
	$(CC) $(CFLAGS) -c -o subspace_checks.o subspace_checks.c

aes_common: AES_common.h AES_common.c
	$(CC) $(CFLAGS) -c -o AES_common10.o AES_common.c -DN_Round=10
	$(CC) $(CFLAGS) -c -o AES_common5.o AES_common.c -DN_Round=5

AES_smallScale: aes_common multiplication AES_smallScaleVersion.c
	$(CC) $(CFLAGS) -o AES_smallScale AES_smallScaleVersion.c AES_common10.o multiplication_smallScale.o

AES_5RoundDistinguisher: aes_common multiplication subspace_checks AES_5RoundDistinguisher.c
	$(CC) $(CFLAGS) -o AES_5RoundDistinguisher AES_5RoundDistinguisher.c AES_common5.o subspace_checks.o multiplication_smallScale.o

AES_5RoundDistinguisher_hashTable: aes_common multiplication subspace_checks AES_5RoundDistinguisher_hashTable.c
	$(CC) $(CFLAGS) -o AES_5RoundDistinguisher_hashTable AES_5RoundDistinguisher_hashTable.c AES_common5.o subspace_checks.o multiplication_smallScale.o

clean:
	$(RM) -f AES_common10.o AES_common5.o 
	$(RM) -f multiplication_smallScale.o 
	$(RM) -f subspace_checks.o
	$(RM) -f AES_smallScale
	$(RM) -f AES_5RoundDistinguisher
	$(RM) -f AES_5RoundDistinguisher_hashTable
	
.PHONY: clean
