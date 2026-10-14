/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Encode/Decode                  *
 * ****************************** */
 
#include <stdint.h>
#include "encode.h"
#include "param.h"
#include "poly.h"

/* u = N / 256
 * m = (q - 1) / 2 * \sum_{i = 0}^{255} \mu_i(x^{ui} +...+ x^{u(i + 1) - 1}) */
void encode(POLY_64 *m, const unsigned char *mu)
{
	uint64_t i, j, p;
	uint8_t x;
	
	for (i = 0; i < 32; i++)
	{
		x = mu[i];
		
		for (j = 0; j < 8; j++, x >>= 1)
		{
			if (!(x & 0x1))
			{
				for (p = 0; p < (N >> 8); p++)
				{
					m->poly[(N >> 8) * (i * 8 + j) + p] = 0; 
				}
			}
			else
			{
				for (p = 0; p < (N >> 8); p++)
				{
					m->poly[(N >> 8) * (i * 8 + j) + p] = (Q - 1) >> 1;
				}
			}
		}
	}
}

/* \mu_i = 0 if |m_{ui}| +...+ |m_{u(i + 1) - 1}| < uq / 4
 *       = 1 otherwise */
void decode(unsigned char *mu, const POLY_64 *m)
{
	uint64_t i, j, p;
	uint64_t tmp, sum;
	
	for (i = 0; i < 32; i++)
	{
		mu[i] = 0;
		
		for (j = 0; j < 8; j++)
		{
			sum = 0;
			for (p = 0; p < (N >> 8); p++)
			{
				tmp = m->poly[(N >> 8) * (i * 8 + j) + p];
				if (tmp > (Q - 1) >> 1)
				{
					sum += Q - tmp;
				}
				else
				{
					sum += tmp;
				}
			}
			
			if (sum >= ((N >> 8) * Q) >> 2)
			{
				mu[i] |= 1 << j;
			}
		}
	}
}
