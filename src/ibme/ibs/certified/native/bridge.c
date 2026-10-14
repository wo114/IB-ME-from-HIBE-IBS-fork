/* Strict process-local ML-DSA bridge. Original reference sources are unchanged. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "fips202.h"

#ifndef IBME_SOURCE_ID
#error "source fingerprint required"
#endif
#define MAX_MESSAGE (2u*1024u*1024u)
static uint8_t tape[32];
static size_t tape_used = 32;
static uint32_t attempts = 0;

static void fail(void) { _Exit(65); }
static void read_exact(void *data, size_t size) {
  if (fread(data, 1, size, stdin) != size) fail();
}
static void eof(void) { if (getchar() != EOF || ferror(stdin)) fail(); }
static uint32_t number(void) {
  uint8_t b[4]; read_exact(b,4);
  return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
}
static void wipe(void *data,size_t size) {
  volatile uint8_t *p=(volatile uint8_t*)data;
  while(size--) *p++=0;
}
void randombytes(uint8_t *out, size_t size) {
  if (size > sizeof(tape)-tape_used) _Exit(70);
  memcpy(out,tape+tape_used,size); tape_used+=size;
}

/* Source uses L*nonce+i as a 16-bit XOF nonce. Abort before repetition. */
#define JOIN_(a,b) a##b
#define JOIN(a,b) JOIN_(a,b)
#define REAL(n) JOIN(__real_,n)
#define WRAPPED(n) JOIN(__wrap_,n)
void REAL(polyvecl_uniform_gamma1)(polyvecl*,const uint8_t[CRHBYTES],uint16_t);
void WRAPPED(polyvecl_uniform_gamma1)(polyvecl *v,const uint8_t seed[CRHBYTES],uint16_t nonce) {
  if (nonce != attempts || (uint32_t)L*nonce+L-1>UINT16_MAX) _Exit(71);
  attempts++;
  REAL(polyvecl_uniform_gamma1)(v,seed,nonce);
}

/* Decode/restore without randomness or challenge signing. */
static int public_from_secret(uint8_t pk[CRYPTO_PUBLICKEYBYTES],const uint8_t sk[CRYPTO_SECRETKEYBYTES]) {
  uint8_t rho[SEEDBYTES],tr[TRBYTES],key[SEEDBYTES],check[CRYPTO_SECRETKEYBYTES],hash[TRBYTES];
  polyvecl matrix[K],s1,s1hat;
  polyveck s2,t0,t1,expected_t0;
  unpack_sk(rho,tr,key,&t0,&s1,&s2,sk);
  for (unsigned i=0;i<L;i++) for (unsigned j=0;j<N;j++)
    if (s1.vec[i].coeffs[j]<-ETA || s1.vec[i].coeffs[j]>ETA) return 0;
  for (unsigned i=0;i<K;i++) for (unsigned j=0;j<N;j++)
    if (s2.vec[i].coeffs[j]<-ETA || s2.vec[i].coeffs[j]>ETA) return 0;
  pack_sk(check,rho,tr,key,&t0,&s1,&s2);
  if(memcmp(check,sk,sizeof(check))) return 0;
  polyvec_matrix_expand(matrix,rho); s1hat=s1; polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1,matrix,&s1hat);
  polyveck_reduce(&t1); polyveck_invntt_tomont(&t1);
  polyveck_add(&t1,&t1,&s2); polyveck_caddq(&t1);
  polyveck_power2round(&t1,&expected_t0,&t1);
  for (unsigned i=0;i<K;i++) for (unsigned j=0;j<N;j++)
    if (t0.vec[i].coeffs[j]!=expected_t0.vec[i].coeffs[j]) return 0;
  pack_pk(pk,rho,&t1); shake256(hash,sizeof(hash),pk,CRYPTO_PUBLICKEYBYTES);
  int ok=memcmp(hash,tr,sizeof(tr))==0;
  wipe(check,sizeof(check));wipe(key,sizeof(key));wipe(&s1,sizeof(s1));wipe(&s2,sizeof(s2));
  return ok;
}

static int canonical_signature(const uint8_t sig[CRYPTO_BYTES]) {
  uint8_t c[CTILDEBYTES],check[CRYPTO_BYTES];polyvecl z;polyveck h;
  if (unpack_sig(c,&z,&h,sig) || polyvecl_chknorm(&z,GAMMA1-BETA)) return 0;
  pack_sig(check,c,&z,&h);
  return memcmp(check,sig,CRYPTO_BYTES)==0;
}

int main(int argc,char **argv) {
  uint8_t pk[CRYPTO_PUBLICKEYBYTES],sk[CRYPTO_SECRETKEYBYTES],sig[CRYPTO_BYTES],ctx[255];
  uint8_t *message=NULL;size_t siglen=0;uint32_t ctxlen,mlen;int ok;
  if(argc!=2) fail();
  if(!strcmp(argv[1],"meta")) {
    eof();
    printf("{\"abi\":1,\"source_id\":\"%s\",\"mode\":%d,\"pk\":%d,\"sk\":%d,\"sig\":%d,\"nonce_attempt_limit\":%u}\n",
      IBME_SOURCE_ID,DILITHIUM_MODE,CRYPTO_PUBLICKEYBYTES,CRYPTO_SECRETKEYBYTES,CRYPTO_BYTES,65536u/L);
    return 0;
  }
  if(!strcmp(argv[1],"keypair")) {
    read_exact(tape,32);eof();tape_used=0;
    if(crypto_sign_keypair(pk,sk) || tape_used!=32) _Exit(70);
    fwrite(pk,1,sizeof(pk),stdout);fwrite(sk,1,sizeof(sk),stdout);
  } else if(!strcmp(argv[1],"public")) {
    read_exact(sk,sizeof(sk));eof();ok=public_from_secret(pk,sk);
    putchar(ok);if(ok) fwrite(pk,1,sizeof(pk),stdout);
  } else if(!strcmp(argv[1],"signature")) {
    read_exact(sig,sizeof(sig));eof();putchar(canonical_signature(sig));
  } else if(!strcmp(argv[1],"sign") || !strcmp(argv[1],"verify")) {
    int signing=!strcmp(argv[1],"sign");
    if(signing) { read_exact(sk,sizeof(sk));read_exact(tape,32);tape_used=0; }
    else { read_exact(pk,sizeof(pk));read_exact(sig,sizeof(sig)); }
    ctxlen=number();if(ctxlen>255)fail();read_exact(ctx,ctxlen);
    mlen=number();if(mlen>MAX_MESSAGE)fail();
    message=malloc(mlen?mlen:1);if(!message)_Exit(72);
    read_exact(message,mlen);eof();
    if(signing) {
      if(!public_from_secret(pk,sk)) _Exit(73);
      if(crypto_sign_signature(sig,&siglen,message,mlen,ctx,ctxlen,sk) || siglen!=CRYPTO_BYTES || tape_used!=32) _Exit(70);
      fwrite(sig,1,siglen,stdout);
    } else putchar(crypto_sign_verify(sig,sizeof(sig),message,mlen,ctx,ctxlen,pk)==0);
  } else fail();
  if(message) {wipe(message,mlen);free(message);}
  wipe(tape,sizeof(tape));wipe(sk,sizeof(sk));
  return ferror(stdout)?74:0;
}
