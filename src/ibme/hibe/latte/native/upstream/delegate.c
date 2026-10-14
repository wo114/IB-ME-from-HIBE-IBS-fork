/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Delegation                     *
 * ****************************** */

#include <stdint.h>
#include "delegate.h"
#include "param.h"
#include "poly.h"
#include "mat.h"
#include "sample_z.h"
#include "ntt.h"
#include "fft.h"
#include "sample_fft.h"
#include "keygen.h"
#include "fastrandombytes.h"
#include "red.h"

#include <gmp.h>

void delegate(MAT_64 *s, const MAT_64 *basis, const POLY_64 *a, const uint64_t l, const unsigned char *seed)
{
	static MAT_FFT fft_basis;
	static MAT_FFT basis_g;
	static MAT_FFT tree_root;
	static POLY_FFT tree_dim2[L * (N - 1)];
	
	static POLY_64 c_ntt;
	static POLY_FFT c;
	static MAT_FFT s_fft;
	static POLY_FFT s_ifft;
	
	static POLY_FFT f_fft, g_fft;
	static POLY_Z f, g, F, G;
	
	static MAT_FFT s_fft_head;
	
	static MAT_FFT s_g;
	static POLY_FFT s_g_det;
	
	static POLY_FFT F_fft, G_fft;
	static POLY_FFT d[L];
	static POLY_FFT k_red_fft;
	static POLY_64 k_red;
	static POLY_64 ks;
	
	uint64_t i, j, k, p;
	
	__float128 tmp;
	
	uint64_t norm;
	
	uint64_t f_det_check;
	
	fastrandombytes_setseed(seed);
	
	poly_z_init(&f, N);
	poly_z_init(&g, N);
	poly_z_init(&F, N);
	poly_z_init(&G, N);
	
	for (i = 0; i < l + 1; i++)
	{
		for (j = 0; j < l + 1; j++)
		{
			for (p = 0; p < N; p++)
			{
				fft_basis.mat[i][j].poly[p] = basis->mat[i][j].poly[p];
			}
			
			fft(&(fft_basis.mat[i][j]), N);
		}
	}
	
	gram(&basis_g, &fft_basis, l + 1, N);
	
	fft_ldl(&tree_root, tree_dim2, &basis_g, l + 1, sigma_l[l]);
	
	while (1)
	{
		for (i = 0; i < l + 1; i++)
		{
			do
			{
				norm = 0;
				
				for (p = 0; p < N; p++)
				{
					/* s_{i, l + 1} <-- (D_{\sigma_l})^N */
					s->mat[i][l + 1].poly[p] = sample_z(0, sigma_l[l]);
					
					c_ntt.poly[p] = -(s->mat[i][l + 1].poly[p]);
					
					norm += s->mat[i][l + 1].poly[p] * s->mat[i][l + 1].poly[p];
				}
				
				ntt(&c_ntt);
				
				/* c = -s_{i, l + 1} * A_l */
				for (p = 0; p < N; p++)
				{
					c_ntt.poly[p] = red_plantard(c_ntt.poly[p], a->poly[p]);
				}
				
				intt(&c_ntt);
				
				for (p = 0; p < N; p++)
				{
					c.poly[p] = c_ntt.poly[p];
				}
				
				fft(&c, N);
				
				/* sample preimage */
				sample_preimage(s_fft.mat[i], &fft_basis, &tree_root, tree_dim2, &c, l + 1, 0);
				
				for (j = 0; j < l + 1; j++)
				{
					for (p = 0; p < N; p++)
					{
						s_ifft.poly[p] = s_fft.mat[i][j].poly[p];
					}
					
					ifft(&s_ifft, N);
					
					for (p = 0; p < N; p++)
					{
						s->mat[i][j].poly[p] = roundq(crealq(s_ifft.poly[p]));
						
						norm += s->mat[i][j].poly[p] * s->mat[i][j].poly[p];
					}
				}
				/* ||(s_{i, 0},...,s_{i, l + 1}|| ?> \sqrt{(l + 2)N} * \sigma_l */
			} while (norm_l[l] < norm);
			
			for (p = 0; p < N; p++)
			{
				s_fft.mat[i][l + 1].poly[p] = s->mat[i][l + 1].poly[p];
			}
			
			fft(&(s_fft.mat[i][l + 1]), N);
		}
		
		/* ModFalcon method to solve NTRU euqation for dim > 2 
		 * Here we only consider l = 1 */
		if (l == 1)
		{
			for (p = 0; p < N; p++)
			{
				f_fft.poly[p] = s_fft.mat[0][1].poly[p] * s_fft.mat[1][2].poly[p] - s_fft.mat[0][2].poly[p] * s_fft.mat[1][1].poly[p];				
				g_fft.poly[p] = s_fft.mat[0][0].poly[p] * s_fft.mat[1][2].poly[p] - s_fft.mat[0][2].poly[p] * s_fft.mat[1][0].poly[p];
			}
		}
		
		ifft(&f_fft, N);
		ifft(&g_fft, N);
		
		f_det_check = 0;
		for (p = 0; p < N; p++)
		{
			tmp = roundq(crealq(f_fft.poly[p]));
			
			f_det_check |= tmp != 0;
			
			mpz_set_si(f.poly[p], tmp);
			mpz_set_si(g.poly[p], roundq(crealq(g_fft.poly[p])));
		}
		
		if (!f_det_check)
		{
			continue;
		}
		
		if (tower_solver(&F, &G, &f, &g, N, l))
		{
			continue;
		}
		
		break;
	}
	
	for (i = 0; i < l + 1; i++)
	{
		for (j = 0; j < l + 2; j++)
		{
			for (p = 0; p < N; p++)
			{
				s_fft_head.mat[i][j].poly[p] = conjq(s_fft.mat[i][j].poly[p]);
			}
		}
	}
	
	/* Since the inf-norm of the output in ModFalcon method is about the magnitude of q^{l+1}, we need the further length reduction by using Cramer's rule */
	for (i = 0; i < l + 1; i++)
	{
		for (j = 0; j < l + 1; j++)
		{
			for (p = 0; p < N; p++)
			{
				s_g.mat[i][j].poly[p] = 0;
			}
			
			for (k = 0; k < l + 2; k++)
			{
				for (p = 0; p < N; p++)
				{
					s_g.mat[i][j].poly[p] = s_g.mat[i][j].poly[p] + s_fft_head.mat[i][k].poly[p] * s_fft.mat[j][k].poly[p];
				}
			}
		}
	}
	
	/* Here we only consider l = 1 */
	if (l == 1)
	{
		for (p = 0; p < N; p++)
		{
			s_g_det.poly[p] = s_g.mat[0][0].poly[p] * s_g.mat[1][1].poly[p] - s_g.mat[0][1].poly[p] * s_g.mat[1][0].poly[p];
		}
	}
	
	for (p = 0; p < N; p++)
	{		
		s->mat[2][0].poly[p] = mpz_get_si(G.poly[p]);
		G_fft.poly[p] = s->mat[2][0].poly[p];
		
		s->mat[2][1].poly[p] = mpz_get_si(F.poly[p]);
		F_fft.poly[p] = s->mat[2][1].poly[p];
	}
	
	fft(&F_fft, N);
	fft(&G_fft, N);
	
	for (i = 0; i < l + 1; i++)
	{
		for (p = 0; p < N; p++)
		{
			d[i].poly[p] = s_fft_head.mat[i][0].poly[p] * G_fft.poly[p] + s_fft_head.mat[i][1].poly[p] * F_fft.poly[p];
		}
	}
	
	/* Here we only consider l = 1 */
	if (l == 1)
	{
		for (p = 0; p < N; p++)
		{
			k_red_fft.poly[p] = (d[0].poly[p] * s_g.mat[1][1].poly[p] - s_g.mat[0][1].poly[p] * d[1].poly[p]) / s_g_det.poly[p];
		}
		
		ifft(&k_red_fft, N);
		
		for (p = 0; p < N; p++)
		{
			k_red.poly[p] = roundq(crealq(k_red_fft.poly[p]));
		}
		
		poly_mul_6464(&ks, &k_red, s->mat[0], N);
		for (p = 0; p < N; p++)
		{
			s->mat[2][0].poly[p] = s->mat[2][0].poly[p] - ks.poly[p];
		}
		
		poly_mul_6464(&ks, &k_red, s->mat[0] + 1, N);
		for (p = 0; p < N; p++)
		{
			s->mat[2][1].poly[p] = s->mat[2][1].poly[p] - ks.poly[p];
		}
		
		poly_mul_6464(&ks, &k_red, s->mat[0] + 2, N);
		for (p = 0; p < N; p++)
		{
			s->mat[2][2].poly[p] = -ks.poly[p];
		}
		
		for (p = 0; p < N; p++)
		{
			k_red_fft.poly[p] = (s_g.mat[0][0].poly[p] * d[1].poly[p] - d[0].poly[p] * s_g.mat[1][0].poly[p]) / s_g_det.poly[p];
		}
		
		ifft(&k_red_fft, N);
		
		for (p = 0; p < N; p++)
		{
			k_red.poly[p] = roundq(crealq(k_red_fft.poly[p]));
		}
		
		poly_mul_6464(&ks, &k_red, s->mat[1], N);
		for (p = 0; p < N; p++)
		{
			s->mat[2][0].poly[p] = s->mat[2][0].poly[p] - ks.poly[p];
		}
		
		poly_mul_6464(&ks, &k_red, s->mat[1] + 1, N);
		for (p = 0; p < N; p++)
		{
			s->mat[2][1].poly[p] = s->mat[2][1].poly[p] - ks.poly[p];
		}
		
		poly_mul_6464(&ks, &k_red, s->mat[1] + 2, N);
		for (p = 0; p < N; p++)
		{
			s->mat[2][2].poly[p] = s->mat[2][2].poly[p] - ks.poly[p];
		}
	}
	
	poly_z_clear(&f, N);
	poly_z_clear(&g, N);
	poly_z_clear(&F, N);
	poly_z_clear(&G, N);
}
