// Exact integer Bareiss arithmetic only. No entropy or secret-value diagnostics.
#include <flint/fmpz_mat.h>
#include <flint/fmpq.h>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    bool projections = false, norms_only = false;
    if (argc == 2) {
        const std::string option(argv[1]);
        if (option == "--version") {
            std::cout << "IBME-EXACT-GRAM/1 FLINT " << FLINT_VERSION << '\n';
            return 0;
        }
        if (option == "--projections") projections = true;
        else if (option == "--norms-only") norms_only = true;
        else return 2;
    } else if (argc != 1) return 2;
    slong n;
    if (!(std::cin >> n) || n < 1 || n > 1536) return 2;
    fmpz_mat_t b, bt, g, augmented, f;
    fmpz_mat_init(b, n, n);
    fmpz_mat_init(bt, n, n);
    fmpz_mat_init(g, n, n);
    const slong columns = projections ? 2*n : n;
    fmpz_mat_init(augmented, n, columns);
    fmpz_mat_init(f, n, columns);
    std::string token;
    for (slong i = 0; i < n; ++i) {
        for (slong j = 0; j < n; ++j) {
            if (!(std::cin >> token) || token.size() > 20000 ||
                fmpz_set_str(fmpz_mat_entry(b, i, j), token.c_str(), 10)) return 3;
        }
    }
    if (std::cin >> token) return 3;
    fmpz_mat_transpose(bt, b);
    fmpz_mat_mul(g, bt, b);
    for (slong i = 0; i < n; ++i) {
        for (slong j = 0; j < n; ++j) {
            fmpz_set(fmpz_mat_entry(augmented, i, j), fmpz_mat_entry(g, i, j));
            if (projections) fmpz_set(fmpz_mat_entry(augmented, i, n+j), fmpz_mat_entry(bt, i, j));
        }
    }
    fmpz_t den, previous;
    fmpz_init(den);
    fmpz_init(previous);
    fmpz_one(previous);
    std::vector<slong> permutation(n);
    for (slong i = 0; i < n; ++i) permutation[i] = i;
    if (fmpz_mat_fflu(f, den, permutation.data(), augmented, 1) != n) return 4;
    for (slong i = 0; i < n; ++i) {
        if (permutation[i] != i || fmpz_sgn(fmpz_mat_entry(f, i, i)) <= 0) return 5;
    }
    fmpq_t q;
    fmpq_init(q);
    size_t emitted = 0;
    auto emit = [&](const fmpz* numerator, const fmpz* denominator) {
        fmpq_set_fmpz_frac(q, numerator, denominator);
        if (fmpz_bits(fmpq_numref(q)) > 65536 || fmpz_bits(fmpq_denref(q)) > 65536) return false;
        char* text = fmpq_get_str(nullptr, 10, q);
        std::string output(text);
        flint_free(text);
        emitted += output.size() + 1;
        if (emitted > (size_t(1) << 30)) return false;
        std::cout << output << '\n';
        return bool(std::cout);
    };
    for (slong i = 0; i < n; ++i) {
        if (!emit(fmpz_mat_entry(f, i, i), previous)) return 6;
        fmpz_set(previous, fmpz_mat_entry(f, i, i));
    }
    if (!norms_only) {
        std::cout << "MU\n";
        for (slong i = 0; i < n; ++i)
            for (slong j = i+1; j < n; ++j)
                if (!emit(fmpz_mat_entry(f, i, j), fmpz_mat_entry(f, i, i))) return 6;
    }
    if (projections) {
        std::cout << "WEIGHTS\n";
        for (slong i = 0; i < n; ++i)
            for (slong j = 0; j < n; ++j)
                if (!emit(fmpz_mat_entry(f, i, n+j), fmpz_mat_entry(f, i, i))) return 6;
    }
    fmpq_clear(q);
    fmpz_clear(previous);
    fmpz_clear(den);
    fmpz_mat_clear(f);
    fmpz_mat_clear(augmented);
    fmpz_mat_clear(g);
    fmpz_mat_clear(bt);
    fmpz_mat_clear(b);
    return 0;
}
