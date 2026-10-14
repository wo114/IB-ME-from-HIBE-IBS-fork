/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Keygen                         *
 * ****************************** */
 
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "keygen.h"
#include "param.h"
#include "fft.h"
#include "ntt.h"
#include "sample_z.h"
#include "poly.h"
#include "mat.h"
#include "fastrandombytes.h"
#include "red.h"

#include <gmp.h>
#include <mpfr.h>
#include <mpc.h>

/* max(||g, -f||, ||qf* / (f * f* + g * g*), qg* / (f * f* + g * g*)) ?> \sigma_0 * \sqrt(2N) */
static int64_t gs_norm(const POLY_64 *f, const POLY_64 *g, const __float128 norm_bound)
{
	static POLY_FFT fft_f, fft_g;
	__complex128 denom;
	__float128 norm2;
	
	__complex128 fft_f_adj, fft_g_adj;
	
	uint64_t i;
	int64_t ret;
	
	uint64_t norm1 = 0;
	
	for (i = 0; i < N; i++)
	{
		norm1 += f->poly[i] * f->poly[i] + g->poly[i] * g->poly[i];
	}
	
	if (norm_bound >= norm1)
	{
		for (i = 0; i < N; i++)
		{
			fft_f.poly[i] = f->poly[i];
			fft_g.poly[i] = g->poly[i];
		}
		
		fft(&fft_f, N);
		fft(&fft_g, N);
		
		for (i = 0; i < N; i++)
		{
			fft_f_adj = conjq(fft_f.poly[i]);
			fft_g_adj = conjq(fft_g.poly[i]);

			denom = fft_f.poly[i] * fft_f_adj + fft_g.poly[i] * fft_g_adj;
			
			fft_f.poly[i] = fft_f_adj / denom;
			fft_g.poly[i] = fft_g_adj / denom;
		}
		
		ifft(&fft_f, N);
		ifft(&fft_g, N);
		
		norm2 = 0;
		for (i = 0; i < N; i++)
		{
			norm2 = norm2 + crealq(fft_f.poly[i]) * crealq(fft_f.poly[i]) + crealq(fft_g.poly[i]) * crealq(fft_g.poly[i]);
		}
		
		norm2 = norm2 * Q;
		norm2 = norm2 * Q;
		
		ret = norm2 > norm_bound;
	}
	else
	{
		ret = 1;
	}

	return ret;
}

/* field norm N(a) from NTRUSolve in Falcon */
static void field_norm(POLY_Z *out, const POLY_Z *a, const uint64_t n)
{
	static POLY_Z a_e, a_o;
	static POLY_Z tmp;
	
	uint64_t i;
	
	poly_z_init(&a_e, n);
	poly_z_init(&a_o, n);
	poly_z_init(&tmp, n);
	
	for (i = 0; i < n; i++)
	{
		mpz_set(a_e.poly[i], a->poly[i << 1]);
		mpz_set(a_o.poly[i], a->poly[(i << 1) + 1]);
	}
	
	poly_mul_zz(out, &a_e, &a_e, n);
	poly_mul_zz(&tmp, &a_o, &a_o, n);
	
	mpz_add(out->poly[0], out->poly[0], tmp.poly[n - 1]);
	for (i = 1; i < n; i++)
	{
		mpz_sub(out->poly[i], out->poly[i], tmp.poly[i - 1]);
	}
	
	poly_z_clear(&a_e, n);
	poly_z_clear(&a_o, n);
	poly_z_clear(&tmp, n);
}

/* g^{x}(x)F'(x^2) from NTRUSolve in Falcon */
static void lift(POLY_Z *out, const POLY_Z *g, const POLY_Z *F_prime, const uint64_t n)
{
	static POLY_Z gx, F_prime_x2;
	
	uint64_t i;
	
	poly_z_init(&gx, n);
	poly_z_init(&F_prime_x2, n);
	
	for (i = 0; i < n; i += 2)
	{
		mpz_set(gx.poly[i], g->poly[i]);
		mpz_neg(gx.poly[i + 1], g->poly[i + 1]);
	}
	
	for (i = 0; i < (n >> 1); i++)
	{
		mpz_set(F_prime_x2.poly[i << 1], F_prime->poly[i]);
	}
	
	poly_mul_zz(out, &gx, &F_prime_x2, n);
	
	poly_z_clear(&gx, n);
	poly_z_clear(&F_prime_x2, n);
}

/* length reduction */
static void reduce_k(POLY_Z *F_red, POLY_Z *G_red, const POLY_Z *f, const POLY_Z *g, const POLY_Z *F, const POLY_Z *G, const uint64_t n, const uint64_t l)
{
	uint64_t i;
	
	static POLY_FFT_HIGH f_hi, g_hi;
	static POLY_FFT_HIGH F_hi, G_hi;
	
	static POLY_FFT_HIGH k_denom;
	static POLY_FFT_HIGH k_fft;
	
	static POLY_FFT_HIGH f_hi_adj, g_hi_adj;
	
	mpfr_t k_round;
	static POLY_Z k_poly, fk, gk;
	
	mpz_t norm_old, norm_new;
	static POLY_Z F_new, G_new;
	
	poly_fft_init_high(&f_hi, n, reduce_k_prec[l]);
	poly_fft_init_high(&g_hi, n, reduce_k_prec[l]);
	
	poly_fft_init_high(&f_hi_adj, n, reduce_k_prec[l]);
	poly_fft_init_high(&g_hi_adj, n, reduce_k_prec[l]);
	
	poly_fft_init_high(&k_denom, n, reduce_k_prec[l]);
	
	poly_fft_init_high(&k_fft, n, reduce_k_prec[l]);
	
	poly_fft_init_high(&F_hi, n, reduce_k_prec[l]);
	poly_fft_init_high(&G_hi, n, reduce_k_prec[l]);
	
	mpz_inits(norm_old, norm_new, NULL);
	
	for (i = 0; i < n; i++)
	{
		mpc_set_z(f_hi.poly[i], f->poly[i], MPC_RNDNN);
		mpc_set_z(g_hi.poly[i], g->poly[i], MPC_RNDNN);
	}
	
	fft_reduce_k(&f_hi, n, l);
	fft_reduce_k(&g_hi, n, l);
	
	for (i = 0; i < n; i++)
	{
		mpc_conj(f_hi_adj.poly[i], f_hi.poly[i], MPC_RNDNN);
		mpc_conj(g_hi_adj.poly[i], g_hi.poly[i], MPC_RNDNN);

		mpc_mul(k_denom.poly[i], f_hi.poly[i], f_hi_adj.poly[i], MPC_RNDNN);
		mpc_fma(k_denom.poly[i], g_hi.poly[i], g_hi_adj.poly[i], k_denom.poly[i], MPC_RNDNN);
	}
	
	for (i = 0; i < n; i++)
	{
		mpz_set(F_red->poly[i], F->poly[i]);
		mpz_set(G_red->poly[i], G->poly[i]);
		
		mpz_addmul(norm_old, F_red->poly[i], F_red->poly[i]);
		mpz_addmul(norm_old, G_red->poly[i], G_red->poly[i]);
	}
	
	mpfr_init2(k_round, reduce_k_prec[l]);
	poly_z_init(&k_poly, n);
	
	poly_z_init(&fk, n);
	poly_z_init(&gk, n);
	
	poly_z_init(&F_new, n);
	poly_z_init(&G_new, n);
	
	while (1)
	{
		for (i = 0; i < n; i++)
		{
			mpc_set_z(F_hi.poly[i], F_red->poly[i], MPC_RNDNN);
			mpc_set_z(G_hi.poly[i], G_red->poly[i], MPC_RNDNN);
		}
		
		fft_reduce_k(&F_hi, n, l);
		fft_reduce_k(&G_hi, n, l);
		
		for (i = 0; i < n; i++)
		{
			mpc_mul(k_fft.poly[i], F_hi.poly[i], f_hi_adj.poly[i], MPC_RNDNN);
			mpc_fma(k_fft.poly[i], G_hi.poly[i], g_hi_adj.poly[i], k_fft.poly[i], MPC_RNDNN);
			
			mpc_div(k_fft.poly[i], k_fft.poly[i], k_denom.poly[i], MPC_RNDNN);
		}
		
		ifft_reduce_k(&k_fft, n, l);
		
		for (i = 0; i < n; i++)
		{
			mpfr_round(k_round, mpc_realref(k_fft.poly[i]));
			mpfr_get_z(k_poly.poly[i], k_round, MPFR_RNDN);
		}
		
		poly_mul_zz(&fk, f, &k_poly, n);
		poly_mul_zz(&gk, g, &k_poly, n);
		
		for (i = 0; i < n; i++)
		{
			mpz_sub(F_new.poly[i], F_red->poly[i], fk.poly[i]);
			mpz_sub(G_new.poly[i], G_red->poly[i], gk.poly[i]);
			
			mpz_addmul(norm_new, F_new.poly[i], F_new.poly[i]);
			mpz_addmul(norm_new, G_new.poly[i], G_new.poly[i]);
		}
		
		if (mpz_cmp(norm_old, norm_new) <= 0)
		{
			break;
		}
		
		for (i = 0; i < n; i++)
		{
			mpz_set(F_red->poly[i], F_new.poly[i]);
			mpz_set(G_red->poly[i], G_new.poly[i]);
		}
		
		mpz_set(norm_old, norm_new);
		mpz_set_ui(norm_new, 0);
	}
	
	poly_fft_clear_high(&f_hi, n);
	poly_fft_clear_high(&g_hi, n);
	
	poly_fft_clear_high(&f_hi_adj, n);
	poly_fft_clear_high(&g_hi_adj, n);
	
	poly_fft_clear_high(&k_denom, n);
	
	poly_fft_clear_high(&k_fft, n);
	
	poly_fft_clear_high(&F_hi, n);
	poly_fft_clear_high(&G_hi, n);

	mpfr_clear(k_round);
	
	poly_z_clear(&k_poly, n);
	poly_z_clear(&fk, n);
	poly_z_clear(&gk, n);
	
	poly_z_clear(&F_new, n);
	poly_z_clear(&G_new, n);

	mpz_clears(norm_old, norm_new, NULL);
}

/* NTRUSolve from Falcon */
int64_t tower_solver(POLY_Z *F, POLY_Z *G, const POLY_Z *f, const POLY_Z *g, const uint64_t n, const uint64_t l)
{
	mpz_t d, u, v;
	
	int64_t ret;
	
	uint64_t n2 = n >> 1;

	static POLY_Z F_prime, G_prime, F_unred, G_unred;
	static uint64_t initialised;
	
	POLY_Z f_prime, g_prime;
	
	if (n == 1)
	{
		mpz_inits(d, u, v, NULL);
		
		mpz_gcdext(d, u, v, f->poly[0], g->poly[0]);
		
		if (mpz_cmp_ui(d, 1))
		{
			ret = 1;
		}
		else
		{
			mpz_mul_si(F->poly[0], v, -Q);
			mpz_mul_ui(G->poly[0], u, Q);
			
			ret = 0;
		}
		
		mpz_clears(d, u, v, NULL);
		
		return ret;
	}
	else
	{
		if (!initialised)
		{
			poly_z_init(&F_prime, N >> 1);
			poly_z_init(&G_prime, N >> 1);

			poly_z_init(&F_unred, N);
			poly_z_init(&G_unred, N);
			
			initialised = 1;
		}
				
		poly_z_init(&f_prime, n2);
		poly_z_init(&g_prime, n2);
		
		field_norm(&f_prime, f, n2);
		field_norm(&g_prime, g, n2);
		
		ret = tower_solver(&F_prime, &G_prime, &f_prime, &g_prime, n2, l);
		
		if (!ret)
		{
			lift(&F_unred, g, &F_prime, n);
			lift(&G_unred, f, &G_prime, n);
			
			reduce_k(F, G, f, g, &F_unred, &G_unred, n, l);
		}
		
		poly_z_clear(&f_prime, n2);
		poly_z_clear(&g_prime, n2);
		
		if (n == N)
		{
			poly_z_clear(&F_prime, N >> 1);
			poly_z_clear(&G_prime, N >> 1);

			poly_z_clear(&F_unred, N);
			poly_z_clear(&G_unred, N);
			
			initialised = 0;
		}
		
		return ret;
	}
}

/* Generate (f, g, F, G) such that f * G - g * F = q */
static void ntru_basis(POLY_64 *f, POLY_64 *g, POLY_64 *F, POLY_64 *G)
{
	static POLY_Z f_z, g_z, F_z, G_z;
	
	uint64_t i;
	
	poly_z_init(&f_z, N);
	poly_z_init(&g_z, N);
	poly_z_init(&F_z, N);
	poly_z_init(&G_z, N);
	
	while (1)
	{
		/* f, g <-- (D_{\sigma_0})^N */
		sample_0z(f);
		sample_0z(g);
		
		/* Norm check */
		if (gs_norm(f, g, norm_l[0]))
		{
			continue;
		}
		
		for (i = 0; i < N; i++)
		{
			mpz_set_si(f_z.poly[i], f->poly[i]);
			mpz_set_si(g_z.poly[i], g->poly[i]);
		}
		
		/* Find F, G such that f * G - g * F = q */
		if (tower_solver(&F_z, &G_z, &f_z, &g_z, N, 0))
		{
			continue;
		}
		
		break;
	}
	
	for (i = 0; i < N; i++)
	{
		F->poly[i] = mpz_get_si(F_z.poly[i]);
		G->poly[i] = mpz_get_si(G_z.poly[i]);
	}
	
	poly_z_clear(&f_z, N);
	poly_z_clear(&g_z, N);
	poly_z_clear(&F_z, N);
	poly_z_clear(&G_z, N);
}

void keygen(MAT_64 *basis, POLY_64 *h, const unsigned char *seed)
{
	static POLY_64 f_ntt, g_ntt;
	
	uint64_t i;
	
	int64_t tmp;
	
	fastrandombytes_setseed(seed);
	
	do
	{
		ntru_basis(&(basis->mat[0][1]), &(basis->mat[0][0]), &(basis->mat[1][1]), &(basis->mat[1][0]));
		
		memcpy(&f_ntt, &(basis->mat[0][1]), sizeof(POLY_64));
		ntt(&f_ntt);
		
		/* check invertibility of f over R_q */
		tmp = 0;
		for (i = 0; i < N; i++)
		{
			tmp |= !(f_ntt.poly[i]);
		}
	} while (tmp);
	
	memcpy(&g_ntt, &(basis->mat[0][0]), sizeof(POLY_64));
	ntt(&g_ntt);
	
	/* h = g * f^{-1} mod q */
	for (i = 0; i < N; i++)
	{
		h->poly[i] = red_plantard_const(red_plantard(g_ntt.poly[i], inverse(f_ntt.poly[i])), RED_PLANTARD_INV_FACTOR);
	}
	
	/* g | -f
	 * ------
	 * G | -F */
	for (i = 0; i < N; i++)
	{
		basis->mat[0][1].poly[i] = -basis->mat[0][1].poly[i];
		basis->mat[1][1].poly[i] = -basis->mat[1][1].poly[i];
	}
}
