/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Keygen                         *
 * ****************************** */
 
#ifndef _KEYGEN_H
#define _KEYGEN_H

#include "poly.h"
#include "mat.h"

void keygen(MAT_64 *basis, POLY_64 *h, const unsigned char *seed);
int64_t tower_solver(POLY_Z *F, POLY_Z *G, const POLY_Z *f, const POLY_Z *g, const uint64_t n, const uint64_t l);

#endif
