/* Research-only isolated-process ABI. All wire polynomials are coefficients,
 * not native structs/NTT values. No randombytes, rand, fallback or file I/O.
 * One operation per process avoids the upstream static-state concurrency issue.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include "param.h"
#include "poly.h"
#include "mat.h"
#include "keygen.h"
#include "delegate.h"
#include "extract.h"
#include "encrypt.h"
#include "decrypt.h"
#include "ntt.h"
#include "sample_z.h"
#include "fastrandombytes.h"
#include "compat/libXKCP.a.headers/SimpleFIPS202.h"
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error This ABI supports little-endian Linux x86-64 only
#endif
#ifndef IBME_LATTE_SOURCE_ID
#error A verified source fingerprint must be supplied by build.py
#endif

static MAT_64 basis, delegated;
static POLY_64 a[3], t[2], c[3];
static void take(void *p,size_t n) { if(fread(p,1,n,stdin)!=n) _Exit(65); }
static void give(const void *p,size_t n) { if(fwrite(p,1,n,stdout)!=n) _Exit(74); }
static void end(void) { if(fgetc(stdin)!=EOF || ferror(stdin)) _Exit(65); }
static void read_poly(POLY_64 *p,int secret) {
    take(p,sizeof(*p));
    for(size_t i=0;i<N;i++) {
        int64_t v=p->poly[i];
        if(secret ? (v<=-((int64_t)1<<50)||v>=((int64_t)1<<50)) : (v<0||v>=Q)) _Exit(65);
    }
}
static void forward(POLY_64 *p) {
    for(size_t i=0;i<N;i++) { p->poly[i]%=Q; if(p->poly[i]<0) p->poly[i]+=Q; }
    ntt(p);
}
static void backward(POLY_64 *p,int secret) {
    intt(p);
    for(size_t i=0;i<N;i++) {
        p->poly[i]%=Q; if(p->poly[i]<0) p->poly[i]+=Q;
        if(secret && p->poly[i]>Q/2) p->poly[i]-=Q;
    }
}
static void read_basis(MAT_64 *b,size_t dim) {
    for(size_t i=0;i<dim;i++) for(size_t j=0;j<dim;j++) read_poly(&b->mat[i][j],1);
}
static void write_basis(MAT_64 *b,size_t dim) {
    for(size_t i=0;i<dim;i++) for(size_t j=0;j<dim;j++) give(&b->mat[i][j],sizeof(POLY_64));
}
int main(int argc,char **argv) {
    if(argc!=2 || sizeof(int64_t)!=8 || sizeof(POLY_64)!=8192) return 64;
    unsigned char seed[32],mu[32],z[32],status;
    if(!strcmp(argv[1],"meta")) {
        end();
        printf("{\"abi\":\"IBME-LATTE3-COEFF-1\",\"source_id\":\"%s\",\"n\":1024,\"q\":68718428161}\n",IBME_LATTE_SOURCE_ID);
    } else if(!strcmp(argv[1],"setup")) {
        take(seed,32); end(); keygen(&basis,a,seed); backward(a,0);
        give(a,sizeof(POLY_64)); write_basis(&basis,2);
    } else if(!strcmp(argv[1],"delegate")) {
        read_basis(&basis,2); read_poly(a,0); take(seed,32); end();
        forward(a); delegate(&delegated,&basis,a,1,seed); write_basis(&delegated,3);
    } else if(!strcmp(argv[1],"extract")) {
        read_basis(&basis,3); read_poly(a,0); end();
        forward(a); extract(t,&basis,a,2);
        for(size_t i=0;i<2;i++) { backward(t+i,1); give(t+i,sizeof(POLY_64)); }
    } else if(!strcmp(argv[1],"encrypt")) {
        for(size_t i=0;i<3;i++) { read_poly(a+i,0); forward(a+i); }
        take(mu,32); take(seed,32); end(); encrypt(z,c,mu,a,2,seed);
        give(z,32);
        for(size_t i=0;i<3;i++) { backward(c+i,0); give(c+i,sizeof(POLY_64)); }
    } else if(!strcmp(argv[1],"decrypt")) {
        for(size_t i=0;i<3;i++) { read_poly(a+i,0); forward(a+i); }
        for(size_t i=0;i<2;i++) { read_poly(t+i,1); forward(t+i); }
        take(z,32);
        for(size_t i=0;i<3;i++) { read_poly(c+i,0); forward(c+i); }
        end(); status=decrypt(mu,z,c,a,t,2)?1:0; give(&status,1);
        if(!status) give(mu,32);
    } else if(!strcmp(argv[1],"shake")) {
        unsigned char output[64]; take(seed,32); end(); SHAKE256(output,64,seed,32); give(output,64);
    } else if(!strcmp(argv[1],"scalar")) {
        unsigned char kind; take(seed,32); take(&kind,1); end(); if(kind>1) return 65;
        fastrandombytes_setseed(seed);
        for(size_t i=0;i<4096;i++) { int64_t value=sample_z(0,kind?sigma_l[0]:3); give(&value,8); }
    } else return 64;
    return fflush(stdout)?74:0;
}
