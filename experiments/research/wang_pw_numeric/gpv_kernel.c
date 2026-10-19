#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <omp.h>

static inline uint64_t xorshift64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static inline double uniform(uint64_t *s) {
    return ((xorshift64(s) >> 11) + 0.5) * (1.0 / 9007199254740992.0);
}

static inline double gaussian(uint64_t *s) {
    double u1 = uniform(s);
    double u2 = uniform(s);
    return sqrt(-2.0 * log(u1)) * cos(6.2831853071795864769 * u2);
}

/*
 * Column-major arrays:
 *   B[j + i*m]      = basis entry row j, column i
 *   star[j + i*m]   = Gram-Schmidt star, column i
 *   P[j + c*m]      = particular, column c
 *   X[j + c*m]      = output, column c
 */
void sample_x(const int64_t *B, const double *star, const double *norms,
              const int64_t *P, int64_t *X, int m, int w,
              double sigma, int threads) {
#pragma omp parallel num_threads(threads)
    {
        double *center = (double *)malloc((size_t)m * sizeof(double));
        int64_t *out = (int64_t *)malloc((size_t)m * sizeof(int64_t));
        uint64_t rng = 0x9e3779b97f4a7c15ULL ^ (uint64_t)(omp_get_thread_num() + 1) * 0xbf58476d1ce4e5b9ULL;
#pragma omp for schedule(dynamic, 8)
        for (int c = 0; c < w; ++c) {
            const int64_t *p = P + (size_t)c * m;
            int64_t *x = X + (size_t)c * m;
            for (int j = 0; j < m; ++j) {
                center[j] = -(double)p[j];
                out[j] = p[j];
            }
            for (int i = m - 1; i >= 0; --i) {
                const double *s = star + (size_t)i * m;
                double ci = 0.0;
                for (int j = 0; j < m; ++j) ci += s[j] * center[j];
                ci /= norms[i];
                double si = sigma / sqrt(norms[i]);
                long long zi = llround(ci + si * gaussian(&rng));
                const int64_t *b = B + (size_t)i * m;
                for (int j = 0; j < m; ++j) {
                    double v = (double)zi * (double)b[j];
                    center[j] -= v;
                    out[j] += (int64_t)v;
                }
            }
            for (int j = 0; j < m; ++j) x[j] = out[j];
        }
        free(center);
        free(out);
    }
}
