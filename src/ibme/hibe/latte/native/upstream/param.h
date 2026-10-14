#ifndef _PARAM_H
#define _PARAM_H

#include <stdint.h>
#include <quadmath.h>

#define N 1024

#define Q 68718428161LL /* 2^36 - 2^20 + 1 */

#define L 2

static const __float128 sigma_l[L + 1] = {6777.5879662983919609175926Q, 351968.36683734171059914430Q, 22559988.027951553365675150Q}; 

static const __float128 norm_l[L] = {94076310816.589358454827978Q, 380564678412735.11125276429Q};

static const uint64_t reduce_k_prec[L] = {256, 768};
#define FFT_PREC 768

#endif
