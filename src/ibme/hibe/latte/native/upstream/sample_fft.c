/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Lattice Gaussian sampler       *
 * ****************************** */
 
#include <stdint.h>
#include "sample_fft.h"
#include "param.h"
#include "poly.h"
#include "mat.h"
#include "fft.h"
#include "sample_z.h"

/* ffLDL from Falcon (for dim = 2) */
static void fft_ldl_dim2(POLY_FFT *tree_dim2, const POLY_R *d, const POLY_R *d0, const POLY_FFT *d1, const uint64_t n, const __float128 sigma)
{
	uint64_t p;
	
	POLY_R d_new[2];
	static POLY_R d0_new;
	static POLY_FFT d1_new;
	
	if (n == 1)
	{
		tree_dim2->poly[0] = sigma / sqrtq(d0->poly[0]);
	}
	else
	{
		for (p = 0; p < n; p++)
		{
			d_new[0].poly[p] = d0->poly[p];
			tree_dim2->poly[p] = conjq(d1->poly[p]) / d_new[0].poly[p];
			d_new[1].poly[p] = d->poly[p << 1] * d->poly[(p << 1) + 1] / d_new[0].poly[p];
		}
		
		split_fft_r(&d0_new, &d1_new, d_new, n);
		fft_ldl_dim2(tree_dim2 + 1, d_new, &d0_new, &d1_new, n >> 1, sigma);

		split_fft_r(&d0_new, &d1_new, d_new + 1, n);
		fft_ldl_dim2(tree_dim2 + n, d_new + 1, &d0_new, &d1_new, n >> 1, sigma);
	}
}

/* ffLDL from Falcon (dim = 2 or 3, top level)
 * since all nodes except the root only have L[1, 0], we separate the root from the remaining of the tree to save space */
void fft_ldl(MAT_FFT *tree_root, POLY_FFT *tree_dim2, const MAT_FFT *g, const uint64_t dim, const __float128 sigma)
{
	uint64_t p;
	static POLY_R d[L + 1];
	static POLY_R d0;
	static POLY_FFT d1;
	
	const __float128 q2 = ((__uint128_t)Q) * ((__uint128_t)Q);
	
	if (dim == 2)
	{
		for (p = 0; p < N; p++)
		{
			d[0].poly[p] = crealq(g->mat[0][0].poly[p]);
			tree_root->mat[1][0].poly[p] = g->mat[1][0].poly[p] / d[0].poly[p];
			d[1].poly[p] = q2 / d[0].poly[p];
		}
		
		split_fft_r(&d0, &d1, d, N);
		fft_ldl_dim2(tree_dim2, d, &d0, &d1, N >> 1, sigma);

		split_fft_r(&d0, &d1, d + 1, N);
		fft_ldl_dim2(tree_dim2 + N - 1, d + 1, &d0, &d1, N >> 1, sigma);
	}
	else if (dim == 3)
	{
		for (p = 0; p < N; p++)
		{
			d[0].poly[p] = crealq(g->mat[0][0].poly[p]);
			tree_root->mat[1][0].poly[p] = g->mat[1][0].poly[p] / d[0].poly[p];
			d[1].poly[p] = crealq(g->mat[1][1].poly[p]) - (crealq(g->mat[1][0].poly[p]) * crealq(g->mat[1][0].poly[p]) + cimagq(g->mat[1][0].poly[p]) * cimagq(g->mat[1][0].poly[p])) / d[0].poly[p];
			tree_root->mat[2][0].poly[p] = g->mat[2][0].poly[p] / d[0].poly[p];
			tree_root->mat[2][1].poly[p] = (g->mat[2][1].poly[p] - g->mat[2][0].poly[p] * conjq(tree_root->mat[1][0].poly[p])) / d[1].poly[p];
			d[2].poly[p] = q2 / (d[0].poly[p] * d[1].poly[p]);
		}

		split_fft_r(&d0, &d1, d, N);
		fft_ldl_dim2(tree_dim2, d, &d0, &d1, N >> 1, sigma);

		split_fft_r(&d0, &d1, d + 1, N);
		fft_ldl_dim2(tree_dim2 + N - 1, d + 1, &d0, &d1, N >> 1, sigma);

		split_fft_r(&d0, &d1, d + 2, N);
		fft_ldl_dim2(tree_dim2 + ((N - 1) << 1), d + 2, &d0, &d1, N >> 1, sigma);
	}
}

/* ffSampling from Falcon (for dim = 2) */
static void fft_sampling_dim2(POLY_FFT *z, const POLY_FFT *tree_dim2, const POLY_FFT *t, const uint64_t n)
{
	uint64_t n2 = n >> 1;
	
	uint64_t p;
	
	static POLY_FFT t_j;
	
	POLY_FFT t_j_split[2];
	POLY_FFT z_j_split[2];
	
	if (n == 1)
	{
		z[0].poly[0] = sample_z(crealq(t[0].poly[0]), crealq(tree_dim2->poly[0]));
		z[1].poly[0] = sample_z(crealq(t[1].poly[0]), crealq(tree_dim2->poly[0]));
	}
	else
	{
		for (p = 0; p < n; p++)
		{
			t_j.poly[p] = t[1].poly[p];
		}
		
		split_fft(t_j_split, t_j_split + 1, &t_j, n);
		
		fft_sampling_dim2(z_j_split, tree_dim2 + n, t_j_split, n2);
		
		merge_fft(z + 1, z_j_split, z_j_split + 1, n);
		
		for (p = 0; p < n; p++)
		{
			t_j.poly[p] = t[0].poly[p] + (t[1].poly[p] - z[1].poly[p]) * tree_dim2->poly[p];
		}
		
		split_fft(t_j_split, t_j_split + 1, &t_j, n);
		
		fft_sampling_dim2(z_j_split, tree_dim2 + 1, t_j_split, n2);
		
		merge_fft(z, z_j_split, z_j_split + 1, n);		
	}
}

/* ffSampling from Falcon */
static void fft_sampling(POLY_FFT *z, const MAT_FFT *tree_root, const POLY_FFT *tree_dim2, const POLY_FFT *t, const uint64_t dim)
{
	int64_t i, j, p;
	
	static POLY_FFT t_j;
	
	static POLY_FFT t_j_split[2];
	static POLY_FFT z_j_split[2];
	
	for (j = dim - 1; j >= 0; j--)
	{
		for (p = 0; p < N; p++)
		{
			t_j.poly[p] = t[j].poly[p];
		}
		
		for (i = j + 1; i < dim; i++)
		{
			for (p = 0; p < N; p++)
			{
				t_j.poly[p] = t_j.poly[p] + (t[i].poly[p] - z[i].poly[p]) * tree_root->mat[i][j].poly[p];
			}
		}
		
		split_fft(t_j_split, t_j_split + 1, &t_j, N);
		
		fft_sampling_dim2(z_j_split, tree_dim2 + j * (N - 1), t_j_split, N >> 1);
		
		merge_fft(z + j, z_j_split, z_j_split + 1, N);
	}
}

/* Sample preimage 
 * Equivalent to (c, 0) - GPV(B, \sigma, c) */
void sample_preimage(POLY_FFT *s, const MAT_FFT *b, const MAT_FFT *tree_root, const POLY_FFT *tree_dim2, const POLY_FFT *c, const uint64_t dim, const uint64_t is_extract)
{
	static POLY_FFT t[L + 1];
	static POLY_FFT z[L + 1];
	
	uint64_t i, j, p;
	
	/* t = (c, 0) * B^{-1}
	 * Here we only consider dim = 2 or 3 */
	if (dim == 2)
	{
		for (p = 0; p < N; p++)
		{
			t[0].poly[p] = c->poly[p] * b->mat[1][1].poly[p] / Q;			
			t[1].poly[p] = -c->poly[p] * b->mat[0][1].poly[p] / Q;
		}
	}
	else if (dim == 3)
	{
		for (p = 0; p < N; p++)
		{
			t[0].poly[p] = c->poly[p] * (b->mat[1][1].poly[p] * b->mat[2][2].poly[p] - b->mat[1][2].poly[p] * b->mat[2][1].poly[p]) / Q;			
			t[1].poly[p] = c->poly[p] * (b->mat[0][2].poly[p] * b->mat[2][1].poly[p] - b->mat[0][1].poly[p] * b->mat[2][2].poly[p]) / Q;
			t[2].poly[p] = c->poly[p] * (b->mat[0][1].poly[p] * b->mat[1][2].poly[p] - b->mat[0][2].poly[p] * b->mat[1][1].poly[p]) / Q;
		}
	}
	
	/* z = ffSampling(t, tree) */
	fft_sampling(z, tree_root, tree_dim2, t, dim);
	
	/* preimage s = (t - z) * B */
	for (i = 0; i < dim; i++)
	{
		for (p = 0; p < N; p++)
		{
			z[i].poly[p] = t[i].poly[p] - z[i].poly[p];
		}
	}
	
	for (i = is_extract; i < dim; i++)
	{
		for (p = 0; p < N; p++)
		{
			s[i - is_extract].poly[p] = 0;
		}
		
		for (j = 0; j < dim; j++)
		{
			for (p = 0; p < N; p++)
			{
				s[i - is_extract].poly[p] = s[i - is_extract].poly[p] + z[j].poly[p] * b->mat[j][i].poly[p];
			}
		}
	}
}
