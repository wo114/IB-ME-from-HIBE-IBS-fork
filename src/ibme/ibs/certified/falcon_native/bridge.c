/* IBME process boundary around unchanged Falcon v1.2 reference code (MIT).
 * No OS entropy, key/sign retries with new seeds, or alternate signature format.
 * The separately compiled vector driver accepts official test randomness only.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "falcon.h"
#include "inner.h"

#ifndef IBME_LOGN
#error IBME_LOGN is required
#endif
#ifndef IBME_VECTOR_DRIVER
#define IBME_VECTOR_DRIVER 0
#endif
#ifndef IBME_XOF_LIMIT
#define IBME_XOF_LIMIT (16u * 1024u * 1024u)
#endif
#ifndef IBME_REFILL_LIMIT
#define IBME_REFILL_LIMIT 65536u
#endif
#define N ((size_t)1 << IBME_LOGN)
#define PK FALCON_PUBKEY_SIZE(IBME_LOGN)
#define SK FALCON_PRIVKEY_SIZE(IBME_LOGN)
#define SIG FALCON_SIG_PADDED_SIZE(IBME_LOGN)
#define MAX_MESSAGE (2u * 1024u * 1024u)

static void die(void) { exit(70); }
static size_t xof_bytes, refills;
void __real_falcon_inner_i_shake256_extract(inner_shake256_context *, void *, size_t);
void __wrap_falcon_inner_i_shake256_extract(inner_shake256_context *s, void *out, size_t len)
{
    if (len > IBME_XOF_LIMIT - xof_bytes) die();
    xof_bytes += len;
    __real_falcon_inner_i_shake256_extract(s, out, len);
}
void __real_falcon_inner_prng_refill(prng *p);
void __wrap_falcon_inner_prng_refill(prng *p)
{
    if (refills >= IBME_REFILL_LIMIT) die();
    refills++;
    __real_falcon_inner_prng_refill(p);
}
static void input(void *p, size_t n) { if (fread(p, 1, n, stdin) != n) die(); }
static void end(void) { if (getchar() != EOF || ferror(stdin)) die(); }
static void output(const void *p, size_t n) { if (fwrite(p, 1, n, stdout) != n) die(); }
static void boolean(int b) { unsigned char v = b != 0; output(&v, 1); }
static uint32_t length(void)
{
    uint8_t p[4]; input(p, 4);
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static void le32(uint8_t *p, uint32_t n)
{
    p[0]=(uint8_t)n; p[1]=(uint8_t)(n>>8); p[2]=(uint8_t)(n>>16); p[3]=(uint8_t)(n>>24);
}
static uint8_t *message(size_t *len)
{
    static const uint8_t domain[]="IBME/CERTIBS/FALCON-DIGSIG/1";
    uint8_t ctx[255], *p; uint32_t c=length(), m;
    if (c > sizeof ctx) die(); input(ctx,c);
    m=length(); if (m > MAX_MESSAGE) die();
    *len=sizeof domain+8+c+m;
    p=malloc(*len); if (!p) die();
    memcpy(p,domain,sizeof domain); le32(p+sizeof domain,c);
    memcpy(p+sizeof domain+4,ctx,c); le32(p+sizeof domain+4+c,m);
    input(p+sizeof domain+8+c,m); end(); return p;
}

/* Reconstructing h alone does not validate F: falcon_make_public ignores it.
 * Enforce strict codecs, the exact integer NTRU equation, and both keygen
 * norm acceptance bounds before using a restored private key. No entropy.
 */
static int private_public(uint8_t *pk, const uint8_t *sk, void *tmp, size_t tmplen)
{
    int8_t f[N],g[N],F[N],G[N]; int64_t eq[N];
    uint8_t enc[SK]; fpr a[N],b[N],inv[N];
    size_t u=1,v,i,j; unsigned norm=0; int pf=0,pg=0; fpr bn=fpr_zero;
    if (sk[0] != 0x50+IBME_LOGN) return 0;
#define DECODE(x,bits) do { \
    v=Zf(trim_i8_decode)(x,IBME_LOGN,bits,sk+u,SK-u); \
    if (!v || Zf(trim_i8_encode)(enc+u,SK-u,x,IBME_LOGN,bits)!=v) return 0; \
    u+=v; \
} while (0)
    enc[0]=sk[0];
    DECODE(f,Zf(max_fg_bits)[IBME_LOGN]);
    DECODE(g,Zf(max_fg_bits)[IBME_LOGN]);
    DECODE(F,Zf(max_FG_bits)[IBME_LOGN]);
#undef DECODE
    if (u!=SK || memcmp(enc,sk,SK)) return 0;
    if (!Zf(complete_private)(G,f,g,F,IBME_LOGN,tmp)) return 0;
    memset(eq,0,sizeof eq);
    for (i=0;i<N;i++) {
        pf+=f[i]; pg+=g[i];
        norm+=(unsigned)((int)f[i]*f[i]+(int)g[i]*g[i]);
        for (j=0;j<N;j++) {
            int64_t z=(int64_t)f[i]*G[j]-(int64_t)g[i]*F[j];
            if (i+j<N) eq[i+j]+=z; else eq[i+j-N]-=z;
        }
    }
    if (!(pf&1) || !(pg&1) || norm>=16823 || eq[0]!=12289) return 0;
    for (i=1;i<N;i++) if (eq[i]) return 0;
    for (i=0;i<N;i++) { a[i]=fpr_of(f[i]); b[i]=fpr_of(g[i]); }
    Zf(FFT)(a,IBME_LOGN); Zf(FFT)(b,IBME_LOGN);
    Zf(poly_invnorm2_fft)(inv,a,b,IBME_LOGN);
    Zf(poly_adj_fft)(a,IBME_LOGN); Zf(poly_adj_fft)(b,IBME_LOGN);
    Zf(poly_mulconst)(a,fpr_q,IBME_LOGN); Zf(poly_mulconst)(b,fpr_q,IBME_LOGN);
    Zf(poly_mul_autoadj_fft)(a,inv,IBME_LOGN); Zf(poly_mul_autoadj_fft)(b,inv,IBME_LOGN);
    Zf(iFFT)(a,IBME_LOGN); Zf(iFFT)(b,IBME_LOGN);
    for (i=0;i<N;i++) { bn=fpr_add(bn,fpr_sqr(a[i])); bn=fpr_add(bn,fpr_sqr(b[i])); }
    if (!fpr_lt(bn,fpr_bnorm_max)) return 0;
    return falcon_make_public(pk,PK,sk,SK,tmp,tmplen)==0;
}
static int canonical(const uint8_t *sig)
{
    int16_t s[N]; uint8_t enc[SIG]; size_t used,i;
    if (sig[0]!=0x30+IBME_LOGN) return 0;
    used=Zf(comp_decode)(s,IBME_LOGN,sig+41,SIG-41);
    if (!used || Zf(comp_encode)(enc,SIG-41,s,IBME_LOGN)!=used
        || memcmp(enc,sig+41,used)) return 0;
    for (i=41+used;i<SIG;i++) if (sig[i]) return 0;
    return 1;
}
int main(int argc, char **argv)
{
    uint8_t sk[SK],pk[PK],sig[FALCON_SIG_COMPRESSED_MAXSIZE(IBME_LOGN)],seed[48],nonce[40];
    size_t slen=SIG,mlen; uint8_t *msg; int r;
    shake256_context rng,hash;
    size_t tmplen=FALCON_TMPSIZE_SIGNDYN(IBME_LOGN);
    void *tmp=malloc(tmplen);
    if (!tmp || argc!=2) die();
    if (!strcmp(argv[1],"meta")) {
        end();
        printf("{\"abi\":1,\"source_id\":\"%s\",\"logn\":%u,\"pk\":%u,\"sk\":%u,\"sig\":%u,\"fpemu\":true,\"vector_driver\":%s,\"xof_limit\":%u,\"refill_limit\":%u}",
            IBME_SOURCE_ID,(unsigned)IBME_LOGN,(unsigned)PK,(unsigned)SK,(unsigned)SIG,
            IBME_VECTOR_DRIVER ? "true":"false",(unsigned)IBME_XOF_LIMIT,(unsigned)IBME_REFILL_LIMIT);
    } else if (!strcmp(argv[1],"keypair") || (IBME_VECTOR_DRIVER && !strcmp(argv[1],"kat-keypair"))) {
        size_t seedlen=!strcmp(argv[1],"keypair") ? 32 : 48;
        input(seed,seedlen); end(); shake256_init_prng_from_seed(&rng,seed,seedlen);
        if (falcon_keygen_make(&rng,IBME_LOGN,sk,SK,pk,PK,tmp,tmplen)) die();
        output(pk,PK); output(sk,SK);
    } else if (!strcmp(argv[1],"public")) {
        input(sk,SK); end(); r=private_public(pk,sk,tmp,tmplen);
        boolean(r); if (r) output(pk,PK);
    } else if (!strcmp(argv[1],"signature")) {
        input(sig,SIG); end(); boolean(canonical(sig));
    } else if (!strcmp(argv[1],"sign")) {
        input(sk,SK); input(seed,32); msg=message(&mlen);
        if (!private_public(pk,sk,tmp,tmplen)) die();
        shake256_init_prng_from_seed(&rng,seed,32);
        if (falcon_sign_dyn(&rng,sig,&slen,FALCON_SIG_PADDED,sk,SK,msg,mlen,tmp,tmplen) || slen!=SIG) die();
        output(sig,slen); free(msg);
    } else if (!strcmp(argv[1],"verify")) {
        input(pk,PK); input(sig,SIG); msg=message(&mlen);
        boolean(canonical(sig) && falcon_verify(sig,SIG,FALCON_SIG_PADDED,pk,PK,msg,mlen,tmp,tmplen)==0);
        free(msg);
    } else if (IBME_VECTOR_DRIVER && (!strcmp(argv[1],"kat-sign") || !strcmp(argv[1],"kat-sign-padded"))) {
        input(sk,SK); input(nonce,40); input(seed,48); mlen=length();
        if (mlen>MAX_MESSAGE) die(); msg=malloc(mlen+1); if (!msg) die(); input(msg,mlen); end();
        if (!private_public(pk,sk,tmp,tmplen)) die();
        shake256_init_prng_from_seed(&rng,seed,48); shake256_init(&hash);
        shake256_inject(&hash,nonce,40); shake256_inject(&hash,msg,mlen);
        int type=!strcmp(argv[1],"kat-sign-padded") ? FALCON_SIG_PADDED : FALCON_SIG_COMPRESSED;
        slen=type==FALCON_SIG_PADDED ? SIG : sizeof sig;
        if (falcon_sign_dyn_finish(&rng,sig,&slen,type,sk,SK,&hash,nonce,tmp,tmplen)) die();
        output(sig,slen); free(msg);
    } else if (IBME_VECTOR_DRIVER && (!strcmp(argv[1],"kat-verify") || !strcmp(argv[1],"kat-verify-padded"))) {
        input(pk,PK); slen=length(); if (slen>sizeof sig) die(); input(sig,slen);
        mlen=length(); if (mlen>MAX_MESSAGE) die(); msg=malloc(mlen+1); if (!msg) die(); input(msg,mlen); end();
        int type=!strcmp(argv[1],"kat-verify-padded") ? FALCON_SIG_PADDED : FALCON_SIG_COMPRESSED;
        boolean(falcon_verify(sig,slen,type,pk,PK,msg,mlen,tmp,tmplen)==0); free(msg);
    } else die();
    memset(sk,0,sizeof sk); memset(seed,0,sizeof seed); free(tmp);
    return fflush(stdout) ? 70 : 0;
}
