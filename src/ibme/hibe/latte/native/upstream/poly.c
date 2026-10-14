/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Polynomial arithmetic          *
 * ****************************** */
 
#include <stdint.h>
#include "poly.h"
#include "param.h"

#include <gmp.h>

/* Karatsuba multiplication */
static void karatsuba_zz(mpz_t *out, const mpz_t *a, const mpz_t *b, const uint64_t n)
{
	mpz_t ax[N >> 1], bx[N >> 1];
	mpz_t axbx[N];
	
	uint64_t i, j;
	uint64_t n2 = n >> 1;
	
	if (n <= 16)
	{
		for (i = 0; i < (n << 1); i++)
		{
			mpz_set_ui(out[i], 0);
		}
		
		for (i = 0; i < n; i++)
		{
			for (j = 0; j < n; j++)
			{
				mpz_addmul(out[i + j], a[i], b[j]);
			}
		}
	}
	else
	{
		for (i = 0; i < n2; i++)
		{
			mpz_inits(ax[i], bx[i], axbx[i], axbx[i + n2], NULL);
			
			mpz_add(ax[i], a[i], a[i + n2]);
			mpz_add(bx[i], b[i], b[i + n2]);
		}
		
		karatsuba_zz(out, a, b, n2);
		karatsuba_zz(out + n, a + n2, b + n2, n2);
		karatsuba_zz(axbx, ax, bx, n2);
		
		for (i = 0; i < n; i++)
		{
			mpz_sub(axbx[i], axbx[i], out[i]);
			mpz_sub(axbx[i], axbx[i], out[i + n]);
		}
		
		for (i = 0; i < n; i++)
		{
			mpz_add(out[i + n2], out[i + n2], axbx[i]);
		}
		
		for (i = 0; i < n2; i++)
		{
			mpz_clears(ax[i], bx[i], axbx[i], axbx[i + n2], NULL);
		}
	}
}

static void karatsuba_6464(int64_t *out, const int64_t *a, const int64_t *b, const uint64_t n)
{
	int64_t ax[N >> 1];
	int64_t bx[N >> 1];
	int64_t axbx[N];
	int64_t tmp;
	
	uint64_t i, j;
	uint64_t n2 = n >> 1;
	
	if (n <= 16)
	{
		for (i = 0; i < (n << 1); i++)
		{
			out[i] = 0;
		}
		
		for (i = 0; i < n; i++)
		{
			for (j = 0; j < n; j++)
			{
				tmp = a[i] * b[j];
				out[i + j] = out[i + j] + tmp;
			}
		}
	}
	else
	{
		for (i = 0; i < n2; i++)
		{
			ax[i] = a[i] + a[i + n2];
			bx[i] = b[i] + b[i + n2];
		}
		
		karatsuba_6464(out, a, b, n2);
		karatsuba_6464(out + n, a + n2, b + n2, n2);
		karatsuba_6464(axbx, ax, bx, n2);
		
		for (i = 0; i < n; i++)
		{
			axbx[i] = axbx[i] - out[i];
			axbx[i] = axbx[i] - out[i + n];
		}
		
		for (i = 0; i < n; i++)
		{
			out[i + n2] = out[i + n2] + axbx[i];
		}
	}
}

/* Polynomial multiplication over Z[x] / (x^N + 1) */
void poly_mul_zz(POLY_Z *out, const POLY_Z *a, const POLY_Z *b, const uint64_t n)
{
	static mpz_t tmp[N << 1];
	
	uint64_t i;
	
	for (i = 0; i < (n << 1); i++)
	{
		mpz_init(tmp[i]);
	}
	
	karatsuba_zz(tmp, a->poly, b->poly, n);
	
	for (i = 0; i < n; i++)
	{
		mpz_sub(out->poly[i], tmp[i], tmp[i + n]);
	}
	
	for (i = 0; i < (n << 1); i++)
	{
		mpz_clear(tmp[i]);
	}
}

void poly_mul_6464(POLY_64 *out, const POLY_64 *a, const POLY_64 *b, const uint64_t n)
{
	static int64_t tmp[N << 1];
	
	uint64_t i;
	
	karatsuba_6464(tmp, a->poly, b->poly, n);
	
	for (i = 0; i < n; i++)
	{
		out->poly[i] = tmp[i] - tmp[i + n];
	}
}
