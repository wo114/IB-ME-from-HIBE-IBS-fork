/* OpenSSL-backed FIPS202 API shim, checked against hashlib SHAKE256 in tests. */
#include <openssl/evp.h>
#include <stdlib.h>
void SHAKE256(unsigned char *out, size_t outlen, const unsigned char *in, size_t inlen) {
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx,EVP_shake256(),NULL)!=1 ||
        EVP_DigestUpdate(ctx,in,inlen)!=1 || EVP_DigestFinalXOF(ctx,out,outlen)!=1) _Exit(70);
    EVP_MD_CTX_free(ctx);
}
