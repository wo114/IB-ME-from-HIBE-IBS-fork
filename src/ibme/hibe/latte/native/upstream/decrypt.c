/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Decryption                     *
 * ****************************** */
 
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "decrypt.h"
#include "param.h"
#include "sample_z.h"
#include "poly.h"
#include "ntt.h"
#include "encode.h"
#include "fastrandombytes.h"
#include "red.h"

#include <libXKCP.a.headers/SimpleFIPS202.h>

uint64_t decrypt(unsigned char *mu, const unsigned char *z, const POLY_64 *c, const POLY_64 *a, const POLY_64 *t, const uint64_t l)
{
	static POLY_64 v;
	static POLY_64 e, e_l[L + 1];
	static POLY_64 c_prime[L + 1];
	static POLY_64 m;
	
	uint64_t i, p;
	
	unsigned char seed_in[64];
	unsigned char seed_kdf[32];
	
	/* V = C_l - C_h * t_1 - ... - C_{l-1} * t_{l} */
	memcpy(&v, c + l, sizeof(POLY_64));
	
	for (i = 0; i < l; i++)
	{
		for (p = 0; p < N; p++)
		{
			v.poly[p] = con_add(v.poly[p] - red_plantard(c[i].poly[p], t[i].poly[p]), Q);
		}
	}
	
	intt(&v);
	
	/* seed' = Decode(V) */
	decode(seed_in, &v);
	
	/* seed for DGS is KDF(seed' || Z) */
	memcpy(seed_in + 32, z, 32);
	
	SHAKE256(seed_kdf, 32, seed_in, 64);
	
	fastrandombytes_setseed(seed_kdf);
	
	/* e', e_h', e_1',..., e_l', e_b' <-- D_{\sigma_e}^N */
	sample_e(&e);
	
	ntt(&e);
	
	for (i = 0; i < l + 1; i++)
	{
		sample_e(e_l + i);
		
		ntt(e_l + i);
	}
	
	/* C_i' = A_i * e' + e_i' */
	for (i = 0; i < l; i++)
	{
		for (p = 0; p < N; p++)
		{
			c_prime[i].poly[p] = con_sub(red_plantard(a[i].poly[p], e.poly[p]) + e_l[i].poly[p], Q);
		}
	}
	
	/* m' = Encode(seed') */
	encode(&m, seed_in);
	
	ntt(&m);
	
	/* C_b' = b * e' + e_b' + m' */
	for (p = 0; p < N; p++)
	{
		c_prime[l].poly[p] = con_sub(red_plantard(a[l].poly[p], e.poly[p]) + e_l[l].poly[p], Q);
		c_prime[l].poly[p] = con_sub(c_prime[l].poly[p] + m.poly[p], Q);
	}
	
	/* (C_h', C_1',..., C_l', C_b') ?= (C_h', C_1',..., C_l', C_b') */
	for (i = 0; i < l + 1; i++)
	{
		for (p = 0; p < N; p++)
		{
			if (c_prime[i].poly[p] != c[i].poly[p])
			{
				return 1;
			}
		}
	}
	
	SHAKE256(seed_kdf, 32, seed_in, 32);
	
	/* mu' = Z xor KDF(seed') */
	for (i = 0; i < 32; i++)
	{
		mu[i] = z[i] ^ seed_kdf[i];
	}
	
	return 0;
}
