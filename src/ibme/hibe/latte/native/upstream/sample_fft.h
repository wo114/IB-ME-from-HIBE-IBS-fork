/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Lattice Gaussian sampler       *
 * ****************************** */
 
#ifndef _SAMPLE_FFT_H
#define _SAMPLE_FFT_H

#include <stdint.h>
#include "mat.h"

void fft_ldl(MAT_FFT *tree_root, POLY_FFT *tree_dim2, const MAT_FFT *g, const uint64_t dim, const __float128 sigma);
void sample_preimage(POLY_FFT *s, const MAT_FFT *b, const MAT_FFT *tree_root, const POLY_FFT *tree_dim2, const POLY_FFT *c, const uint64_t dim, const uint64_t is_extract);

#endif
