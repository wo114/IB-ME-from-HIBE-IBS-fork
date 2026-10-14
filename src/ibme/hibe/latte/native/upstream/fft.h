/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * FFT                            *
 * ****************************** */
 
#ifndef _FFT_H
#define _FFT_H

#include <stdint.h>
#include "poly.h"

void fft_reduce_k(POLY_FFT_HIGH *a, const uint64_t n, const uint64_t l);
void ifft_reduce_k(POLY_FFT_HIGH *a, const uint64_t n, const uint64_t l);
void fft(POLY_FFT *a, const uint64_t n);
void ifft(POLY_FFT *a, const uint64_t n);
void split_fft(POLY_FFT *f0, POLY_FFT *f1, const POLY_FFT *a, const uint64_t n);
void merge_fft(POLY_FFT *a, const POLY_FFT *f0, const POLY_FFT *f1, const uint64_t n);
void split_fft_r(POLY_R *f0, POLY_FFT *f1, const POLY_R *a, const uint64_t n);

#endif
