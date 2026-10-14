/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Extraction                     *
 * ****************************** */
 
#ifndef _EXTRACT_H
#define _EXTRACT_H

#include <stdint.h>
#include "poly.h"
#include "mat.h"

void extract(POLY_64 *t, const MAT_64 *basis, const POLY_64 *a, const uint64_t l);

#endif
