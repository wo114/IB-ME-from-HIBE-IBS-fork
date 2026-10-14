/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Decryption                     *
 * ****************************** */
 
#ifndef _DECRYPT_H
#define _DECRYPT_H

#include <stdint.h>
#include "poly.h"

uint64_t decrypt(unsigned char *mu, const unsigned char *z, const POLY_64 *c, const POLY_64 *a, const POLY_64 *t, const uint64_t l);

#endif
