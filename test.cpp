#include "util.h"

int main() {
    OpenSSL_add_all_algorithms();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    
    EC_POINT *a[N], *b[N];
    EC_POINT *point = EC_POINT_new(group);
    std::set<EC_POINT*, ECPointComparator> b_set;
    BIGNUM *random_scalar = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    for (int i = 0; i < N; i++) {
        a[i] = EC_POINT_new(group);
        BN_rand(random_scalar, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        EC_POINT_mul(group, a[i], random_scalar, NULL, NULL, NULL);
        b[i] = EC_POINT_new(group);
        BN_rand(random_scalar, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        EC_POINT_mul(group, b[i], random_scalar, NULL, NULL, NULL);
    }
    printf("Testing with N=%d.\n", N);
    clock_t start = clock();
    // for (int i = 0; i < N; i++) b_set.insert(b[i]);
    clock_t end = clock();
    double elapsed_time = ((double)(end-start)) / CLOCKS_PER_SEC;
    printf("insert time: %.6f seconds\n", elapsed_time);
    start = clock();
    // for (int i = 0; i < N; i++) b_set.find(a[i]);
    end = clock();
    elapsed_time = ((double)(end-start)) / CLOCKS_PER_SEC;
    printf("find time: %.6f seconds\n", elapsed_time);
    BIGNUM *x1 = BN_new(), *y1 = BN_new(), *x2 = BN_new(), *y2 = BN_new();
    for (int i = 0; i < N; i++) {
        BN_rand(x1, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        BN_rand(x2, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        BN_rand(y1, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        BN_rand(y2, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    }
    start = clock();
    for (int i = 0; i < N; i++) {
        BN_cmp(x1, x2);
        BN_cmp(y1, y2);
    }
    end = clock();
    elapsed_time = ((double)(end-start)) / CLOCKS_PER_SEC;
    printf("get cord time: %.6f seconds\n", elapsed_time);

    EC_POINT_free(point);
    BN_free(random_scalar);
    BN_CTX_free(ctx);

    return 0;
}


// curve2251-clmul-gcc 
// BENCH: ec_mul                           = 137545 cycles
// BENCH: ec_mul_gen                       = 62064 cycles
// BENCH: ec_mul_pre                       = 117505 cycles
// BENCH: ec_mul_fix                       = 61806 cycles
// BENCH: ec_mul_sim                       = 212834 cycles
// BENCH: ec_mul_sim_gen                   = 213023 cycles


// x64-ecc-128
// BENCH: ed_mul                           = 60273 nanosec
// BENCH: ed_mul_lwnaf                     = 60165 nanosec
// BENCH: ed_mul_gen                       = 24181 nanosec
// BENCH: ed_mul_dig                       = 20666 nanosec
// BENCH: ed_mul_pre                       = 43648 nanosec
// BENCH: ed_mul_fix                       = 24188 nanosec
// BENCH: ed_mul_pre_combs                 = 43633 nanosec
// BENCH: ed_mul_fix_combs                 = 24156 nanosec
// BENCH: ed_mul_sim                       = 76179 nanosec
// BENCH: ed_mul_sim_inter                 = 76283 nanosec
// BENCH: ed_mul_sim_gen                   = 76263 nanosec
// BENCH: ed_mul_sim_lot (2)               = 92559 nanosec
