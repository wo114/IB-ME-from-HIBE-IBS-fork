// Exact negacyclic products. Small signed matrices use two NTT primes;
// public large-modulus rows use FLINT integer polynomials then reduction.
#include <gmp.h>
#include <flint/fmpz.h>
#include <flint/fmpz_poly.h>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>

static uint32_t power(uint64_t a,uint64_t e,uint32_t p){
    uint64_t r=1; for(;e;e>>=1,a=a*a%p) if(e&1)r=r*a%p; return r;
}
static void fft(uint32_t *a,int n,uint32_t p,uint32_t root,bool inv){
    for(int i=1,j=0;i<n;i++){
        int b=n>>1; for(;j&b;b>>=1)j^=b; j^=b;
        if(i<j)std::swap(a[i],a[j]);
    }
    uint32_t w0=power(root,(p-1)/n,p);
    if(inv)w0=power(w0,p-2,p);
    for(int len=2;len<=n;len<<=1){
        uint32_t wl=power(w0,n/len,p);
        for(int i=0;i<n;i+=len){
            uint64_t w=1;
            for(int j=0;j<len/2;j++,w=w*wl%p){
                uint32_t u=a[i+j],v=uint64_t(a[i+j+len/2])*w%p;
                a[i+j]=uint64_t(u)+v>=p?uint64_t(u)+v-p:u+v;
                a[i+j+len/2]=u>=v?u-v:uint64_t(u)+p-v;
            }
        }
    }
    if(inv){uint32_t ni=power(n,p-2,p);for(int i=0;i<n;i++)a[i]=uint64_t(a[i])*ni%p;}
}
static const uint32_t primes[2]={2013265921,1811939329};
static const uint32_t roots[2]={31,13};
static bool degree_ok(int d){return d>=4&&d<=2048&&!(d&(d-1));}
struct Small {
    int rows,cols,d; uint64_t bound=0;
    std::vector<uint32_t> a[2],tw[2],itw[2];
    Small(const int64_t *data,int r,int c,int degree):rows(r),cols(c),d(degree){
        if(!degree_ok(d)||r<1||r>308||c<1||c>153)throw std::runtime_error("shape");
        size_t size=size_t(r)*c*d;
        for(size_t i=0;i<size;i++){
            if(data[i]==INT64_MIN)throw std::runtime_error("coefficient");
            bound=std::max(bound,uint64_t(std::abs(data[i])));
        }
        for(int s=0;s<2;s++){
            auto p=primes[s]; auto psi=power(roots[s],(p-1)/(2*d),p);
            if(power(psi,d,p)!=p-1)throw std::runtime_error("root");
            auto ip=power(psi,p-2,p);tw[s].resize(d);itw[s].resize(d);
            tw[s][0]=itw[s][0]=1;
            for(int h=1;h<d;h++){tw[s][h]=uint64_t(tw[s][h-1])*psi%p;itw[s][h]=uint64_t(itw[s][h-1])*ip%p;}
            a[s].resize(size);
            #pragma omp parallel for num_threads(4)
            for(int poly=0;poly<r*c;poly++){
                auto out=a[s].data()+size_t(poly)*d;
                for(int h=0;h<d;h++){
                    int64_t v=data[size_t(poly)*d+h]%int64_t(p);if(v<0)v+=p;
                    out[h]=uint64_t(v)*tw[s][h]%p;
                }
                fft(out,d,p,roots[s],false);
            }
        }
    }
    void apply(const int64_t *x,int64_t *out){
        uint64_t maxx=0;
        for(size_t i=0;i<size_t(cols)*d;i++){
            if(x[i]==INT64_MIN)throw std::runtime_error("input");
            maxx=std::max(maxx,uint64_t(std::abs(x[i])));
        }
        uint64_t modulus=uint64_t(primes[0])*primes[1];
        if(__int128(bound)*maxx*cols*d>=modulus/2)throw std::runtime_error("CRT range");
        std::vector<uint32_t> result[2];
        for(int s=0;s<2;s++){
            auto p=primes[s];std::vector<uint32_t> b(size_t(cols)*d);
            #pragma omp parallel for num_threads(4)
            for(int j=0;j<cols;j++){
                auto bp=b.data()+size_t(j)*d;
                for(int h=0;h<d;h++){int64_t v=x[size_t(j)*d+h]%int64_t(p);if(v<0)v+=p;bp[h]=uint64_t(v)*tw[s][h]%p;}
                fft(bp,d,p,roots[s],false);
            }
            result[s].resize(size_t(rows)*d);
            #pragma omp parallel for num_threads(4)
            for(int i=0;i<rows;i++){
                auto dst=result[s].data()+size_t(i)*d;
                for(int h=0;h<d;h++){
                    uint64_t v=0;
                    for(int j=0;j<cols;j++){
                        v+=uint64_t(a[s][(size_t(i)*cols+j)*d+h])*b[size_t(j)*d+h];
                        if(j%4==3)v%=p;
                    }
                    dst[h]=v%p;
                }
                fft(dst,d,p,roots[s],true);
                for(int h=0;h<d;h++)dst[h]=uint64_t(dst[h])*itw[s][h]%p;
            }
        }
        uint64_t inv=power(primes[0]%primes[1],primes[1]-2,primes[1]);
        for(size_t i=0;i<size_t(rows)*d;i++){
            uint64_t r0=result[0][i],r1=result[1][i];
            uint64_t delta=(r1+primes[1]-r0%primes[1])%primes[1];
            uint64_t v=r0+uint64_t(primes[0])*(delta*inv%primes[1]);
            out[i]=v>modulus/2?-int64_t(modulus-v):int64_t(v);
        }
    }
};
struct Wide {
    int cols,d; std::vector<fmpz_poly_struct> a;
    Wide(const unsigned char *data,int width,int c,int degree):cols(c),d(degree),a(c){
        if(!degree_ok(d)||c<1||c>461||width<1||width>64)throw std::runtime_error("shape");
        mpz_t z;mpz_init(z);fmpz_t v;fmpz_init(v);
        for(int j=0;j<c;j++){
            fmpz_poly_init2(&a[j],d);
            for(int h=0;h<d;h++){
                mpz_import(z,width,1,1,1,0,data+(size_t(j)*d+h)*width);
                fmpz_set_mpz(v,z);fmpz_poly_set_coeff_fmpz(&a[j],h,v);
            }
        }
        fmpz_clear(v);mpz_clear(z);
    }
    ~Wide(){for(auto &p:a)fmpz_poly_clear(&p);}
    void apply(const int64_t *x,const unsigned char *qraw,int width,unsigned char *out){
        fmpz_poly_t acc,tmp,b;fmpz_poly_init(acc);fmpz_poly_init(tmp);fmpz_poly_init2(b,d);
        for(int j=0;j<cols;j++){
            fmpz_poly_zero(b);
            for(int h=0;h<d;h++)fmpz_poly_set_coeff_si(b,h,x[size_t(j)*d+h]);
            fmpz_poly_mul(tmp,&a[j],b);fmpz_poly_add(acc,acc,tmp);
        }
        mpz_t z;mpz_init(z);mpz_import(z,width,1,1,1,0,qraw);
        fmpz_t q,v,w;fmpz_init(q);fmpz_init(v);fmpz_init(w);fmpz_set_mpz(q,z);
        if(fmpz_cmp_ui(q,2)<0)throw std::runtime_error("modulus");
        std::vector<unsigned char> buf(width);
        for(int h=0;h<d;h++){
            fmpz_poly_get_coeff_fmpz(v,acc,h);fmpz_poly_get_coeff_fmpz(w,acc,h+d);
            fmpz_sub(v,v,w);fmpz_mod(v,v,q);fmpz_get_mpz(z,v);
            size_t count=0;std::fill(buf.begin(),buf.end(),0);
            mpz_export(buf.data(),&count,1,1,1,0,z);
            if(count>size_t(width))throw std::runtime_error("output");
            std::memset(out+size_t(h)*width,0,width);
            std::memcpy(out+size_t(h+1)*width-count,buf.data(),count);
        }
        fmpz_clear(q);fmpz_clear(v);fmpz_clear(w);mpz_clear(z);
        fmpz_poly_clear(acc);fmpz_poly_clear(tmp);fmpz_poly_clear(b);
    }
};
extern "C" {
const char *sg_source_id(){return SG_SOURCE_ID;}
void *sg_small_new(const int64_t *x,int r,int c,int d){try{return new Small(x,r,c,d);}catch(...){return nullptr;}}
void sg_small_free(void *p){delete static_cast<Small*>(p);}
int sg_small_apply(void *p,const int64_t *x,int64_t *out){try{static_cast<Small*>(p)->apply(x,out);return 0;}catch(...){return 1;}}
void *sg_wide_new(const unsigned char *x,int w,int c,int d){try{return new Wide(x,w,c,d);}catch(...){return nullptr;}}
void sg_wide_free(void *p){delete static_cast<Wide*>(p);}
int sg_wide_apply(void *p,const int64_t *x,const unsigned char *q,int w,unsigned char *out){try{static_cast<Wide*>(p)->apply(x,q,w,out);return 0;}catch(...){return 1;}}
}
