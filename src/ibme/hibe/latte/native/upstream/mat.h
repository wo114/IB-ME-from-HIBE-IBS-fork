/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Matrice arithmetic             *
 * ****************************** */
 
#ifndef _MAT_H
#define _MAT_H

#include "param.h"
#include "poly.h"

typedef struct 
{
	POLY_FFT mat[L + 1][L + 1];
} MAT_FFT;

typedef struct 
{
	POLY_64 mat[L + 1][L + 1];
} MAT_64;

void gram(MAT_FFT *out, const MAT_FFT *a, const uint64_t dim, const uint64_t n);

#endif
