#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define ROTRIGHT(word,bits) (((word) >> (bits)) | ((word) << (32-(bits))))
#define SSIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SSIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// Supposed incorrect implimentation from NIST.
// BSIG0 is replaced with EP0 and BSIG1 is replaced with EP0 in the implimentation.
#define BSIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define BSIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))


#define HASH_LEN 64

char* sha256(char* toHash) {

	unsigned long k[64] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
		0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
		0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
		0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
		0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
		0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
		0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
		0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
		0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};

	unsigned long static H0 = 0x6a09e667;
	unsigned long static H1 = 0xbb67ae85;
	unsigned long static H2 = 0x3c6ef372;
	unsigned long static H3 = 0xa54ff53a;
	unsigned long static H4 = 0x510e527f;
	unsigned long static H5 = 0x9b05688c;
	unsigned long static H6 = 0x1f83d9ab;
	unsigned long static H7 = 0x5be0cd19;

	unsigned long W[64];

	for (int t = 0; t <= 15; t++)
	{
		W[t] = toHash[t] & 0xFFFFFFFF;
	}

	for (int t = 16; t <= 63; t++)
	{
		// Also taken from spec.
		W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];

		// Have to make sure we are still dealing with 32 bit numbers.
		W[t] = W[t] & 0xFFFFFFFF;
	}

	unsigned long temp1;
	unsigned long temp2;
	unsigned long a = H0;
	unsigned long b = H1;
	unsigned long c = H2;
	unsigned long d = H3;
	unsigned long e = H4;
	unsigned long f = H5;
	unsigned long g = H6;
	unsigned long h = H7;

	for (int t = 0; t < 64; t++)
	{
		// Seems the Official spec is wrong!? BSIG1 is incorrect.
		// Replacing BSIG1 with EP1.
		temp1 = h + EP1(e) + CH(e, f, g) + k[t] + W[t];

		// Seems the Official spec is wrong!? BSIG0 is incorrect.
		// Replacing BSIG0 with EP0.
		temp2 = EP0(a) + MAJ(a, b, c);

		// Do the working variables operations as per NIST.
		h = g;
		g = f;
		f = e;
		e = (d + temp1) & 0xFFFFFFFF; // Makes sure that we are still using 32 bits.
		d = c;
		c = b;
		b = a;
		a = (temp1 + temp2) & 0xFFFFFFFF; // Makes sure that we are still using 32 bits.

	}

	H0 = (H0 + a) & 0xFFFFFFFF;
	H1 = (H1 + b) & 0xFFFFFFFF;
	H2 = (H2 + c) & 0xFFFFFFFF;
	H3 = (H3 + d) & 0xFFFFFFFF;
	H4 = (H4 + e) & 0xFFFFFFFF;
	H5 = (H5 + f) & 0xFFFFFFFF;
	H6 = (H6 + g) & 0xFFFFFFFF;
	H7 = (H7 + h) & 0xFFFFFFFF;

	char result[HASH_LEN] = { 0 };
	char buffer[HASH_LEN] = { 0 };
	_ltoa_s(H0, buffer, HASH_LEN, 16);
	strcat_s(result, HASH_LEN, buffer);
	memset(buffer, 0, HASH_LEN);
	_ltoa_s(H1, buffer, HASH_LEN, 16);
	strcat_s(result, HASH_LEN, buffer);
	memset(buffer, 0, HASH_LEN);
	_ltoa_s(H2, buffer, HASH_LEN, 16);
	strcat_s(result, HASH_LEN, buffer);
	memset(buffer, 0, HASH_LEN);
	_ltoa_s(H3, buffer, HASH_LEN, 16);
	strcat_s(result, HASH_LEN, buffer);
	memset(buffer, 0, HASH_LEN);
	_ltoa_s(H4, buffer, HASH_LEN, 16);
	strcat_s(result, HASH_LEN, buffer);
	memset(buffer, 0, HASH_LEN);
	_ltoa_s(H5, buffer, HASH_LEN, 16);
	strcat_s(result, HASH_LEN, buffer);
	memset(buffer, 0, HASH_LEN);
	_ltoa_s(H6, buffer, HASH_LEN, 16);
	strcat_s(result, HASH_LEN, buffer);
	memset(buffer, 0, HASH_LEN);
	_ltoa_s(H7, buffer, HASH_LEN, 16);
	strcat_s(result, HASH_LEN, buffer);

	return result;
}


int main(int argc, char * argv[])
{
	char filename[25] = { 0 };
	FILE* f = NULL;
	errno_t err;
	int idn = 0;
	int fileRowsCount = 0;

	puts("starting blockchain .....\n");

	if (argc < 2) {
		puts("err: no arguments specified\n");
		puts("usage: ./verifyBl.exe filename [start block]\n");
		return -1;
	}

	if (strlen(argv[1]) > 24) {
		puts("err: provided filename too long\n");
		return -1;
	}

	strcpy_s(filename, sizeof(filename), argv[1]);

	puts("loading bunch of transactions...\n");

	err = fopen_s(&f, filename, "r");
	if (err) {
		perror("err: can't open transaction file\n");
		return -1;
	}
	fscanf_s(f, "%d", &fileRowsCount);
	printf("rows count: %d\n", fileRowsCount);

	char prev[HASH_LEN] = { '1', '2', '3', 'a', 's', 'd', 'f', '\0' };
	char calc[HASH_LEN] = {0};
	char current[HASH_LEN] = {0};

	while (fileRowsCount > 0) {
		fscanf_s(f, "%d %s", &idn, &current);

		//calculate hash from prev
		strcpy_s(calc, HASH_LEN, sha256(prev));

		if (memcmp(calc, current, HASH_LEN) != 0) {
			printf("%s NOK", current);
		}
		else {
			printf("%s OK", current);
		}
		fileRowsCount--;
		strcpy_s(prev, HASH_LEN, current);
	}

	fclose(f);

    return 0;
}
