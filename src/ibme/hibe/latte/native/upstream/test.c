/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Benchmark                      *
 * ****************************** */
  
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "param.h"
#include "poly.h"
#include "mat.h"
#include "keygen.h"
#include "randombytes.h"
#include "extract.h"
#include "encrypt.h"
#include "decrypt.h"
#include "delegate.h"
#include "cpucycles.h"

#define BENCHMARK_ROUND 1000

int main()
{
	uint64_t i, r;
	unsigned char seed[32];
	unsigned char mu[32];
	unsigned char z[32];
	
	uint64_t ret1, ret2;
	
	static MAT_64 basis[L];
	static POLY_64 h;
	static POLY_64 a[L + 1];
	static POLY_64 t[L];
	static POLY_64 c[L + 1];
	
	long long cycle1, cycle2, cycle3, cycle4, cycle5, cycle6, cycle7, cycle8, cycle9, cycle10, cycle11, cycle12, cycle13, cycle14;
	
	srand(time(NULL));
	
	fprintf(stderr, "Latte-3 benchmark\n");
	for (r = 0; r < BENCHMARK_ROUND; r++)
	{
		fprintf(stderr, "%lu\n", r);
		
		randombytes(seed, 32);
		
		cycle1 = cpucycles();
		keygen(basis, &h, seed);
		cycle2 = cpucycles();
		
		for (i = 0; i < N; i++)
		{
			a[0].poly[i] = h.poly[i];
			a[1].poly[i] = rand() % Q;
			a[2].poly[i] = rand() % Q;
		}
		
		cycle3 = cpucycles();
		extract(t, basis, a + 1, 1);
		cycle4 = cpucycles();
		
		randombytes(mu, 32);
		randombytes(seed, 32);
		
		cycle5 = cpucycles();	
		encrypt(z, c, mu, a, 1, seed);
		cycle6 = cpucycles();
		ret1 = decrypt(mu, z, c, a, t, 1);
		cycle7 = cpucycles();
		
		randombytes(seed, 32);
		
		cycle8 = cpucycles();
		delegate(basis + 1, basis, a + 1, 1, seed);
		cycle9 = cpucycles();
		
		cycle10 = cpucycles();
		extract(t, basis + 1, a + 2, 2);
		cycle11 = cpucycles();
		
		randombytes(mu, 32);
		randombytes(seed, 32);
		
		cycle12 = cpucycles();
		encrypt(z, c, mu, a, 2, seed);
		cycle13 = cpucycles();		
		ret2 = decrypt(mu, z, c, a, t, 2);
		cycle14 = cpucycles();
		
		printf("%lld,%lld,%lld,%lld,%lu,%lld,%lld,%lld,%lld,%lu\n", cycle2 - cycle1, cycle4 - cycle3, cycle6 - cycle5, cycle7 - cycle6, ret1, cycle9 - cycle8, cycle11 - cycle10, cycle13 - cycle12, cycle14 - cycle13, ret2);
	}
	
	return 0;
}
