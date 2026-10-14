/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Delegation                     *
 * ****************************** */

#ifndef _DELEGATE_H
#define _DELEGATE_H

#include <stdint.h>
#include "poly.h"
#include "mat.h"

void delegate(MAT_64 *s, const MAT_64 *basis, const POLY_64 *a, const uint64_t l, const unsigned char *seed);

#endif
