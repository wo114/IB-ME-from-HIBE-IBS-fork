/* API-compatible declaration only. Implementation uses OpenSSL EVP SHAKE256. */
#ifndef IBME_LATTE_FIPS202_COMPAT
#define IBME_LATTE_FIPS202_COMPAT
#include <stddef.h>
void SHAKE256(unsigned char *out, size_t outlen, const unsigned char *in, size_t inlen);
#endif
