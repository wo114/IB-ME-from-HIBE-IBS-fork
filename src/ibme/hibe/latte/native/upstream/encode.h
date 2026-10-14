/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Encode/Decode                  *
 * ****************************** */
 
#ifndef _ENCODE_H
#define _ENCODE_H

#include "poly.h"

void encode(POLY_64 *m, const unsigned char *mu);
void decode(unsigned char *mu, const POLY_64 *m);


#endif
