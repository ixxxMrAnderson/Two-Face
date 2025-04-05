#include "util.h"
// #include <fstream>

int BatchPOE(NetIO* ios, int party, int prover, EC_GROUP *group, EC_POINT *A[], EC_POINT *B[], BIGNUM *x, EC_POINT *g_, EC_POINT *g_x, int length, BN_CTX *ctx) {
    unsigned char seed_bytes[16];
    BIGNUM *ORDER = BN_new();
    EC_GROUP_get_order(group, ORDER, ctx);
    EC_POINT *sum_A = EC_POINT_new(group); 
    EC_POINT *sum_B = EC_POINT_new(group); 
    EC_POINT *A_ = EC_POINT_new(group); 
    EC_POINT *B_ = EC_POINT_new(group); 

    if (party == prover) {
        receive_EC_point(group, A_, ios);
        EC_POINT_mul(group, B_, NULL, A_, x, ctx);
        send_EC_point(group, B_, ios);
        ios->recv_data(seed_bytes, sizeof(seed_bytes));
        ios->flush();
    } else {
        BIGNUM *ra = BN_new();
        BN_rand(ra, 256, -1, 0);
        EC_POINT_mul(group, A_, ra, NULL, NULL, ctx);
        send_EC_point(group, A_, ios);
        receive_EC_point(group, B_, ios);
        RAND_bytes(seed_bytes, 16);
        ios->send_data(seed_bytes, sizeof(seed_bytes));
        BN_free(ra);
    }
    PRG *prg = new PRG(seed_bytes);
    EC_POINT **tmp_veca = (EC_POINT **)malloc(length * sizeof(EC_POINT *));
    EC_POINT **tmp_vecb = (EC_POINT **)malloc(length * sizeof(EC_POINT *));
    BIGNUM **q = (BIGNUM **)malloc((length+2) * sizeof(BIGNUM *));
    for (int i = 0; i < length+2; i++) {
        unsigned char q_[32];
        prg->random_data(q_, sizeof(q_));
        q[i] = BN_bin2bn(q_, sizeof(q_), NULL);
        if (i < length) {
            tmp_veca[i] = EC_POINT_new(group);
            tmp_vecb[i] = EC_POINT_new(group);
        }
    }
    ECmul_vector(group, A, tmp_veca, q, length, thread_num);
    ECmul_vector(group, B, tmp_vecb, q, length, thread_num);
    for (int i = 0; i < length+2; i++) {
        if (i < length) {
            EC_POINT_add(group, sum_A, sum_A, tmp_veca[i], ctx);
            EC_POINT_add(group, sum_B, sum_B, tmp_vecb[i], ctx);
        } else if (i == length) {
            EC_POINT *tmp_A = EC_POINT_new(group), *tmp_B = EC_POINT_new(group);
            EC_POINT_mul(group, tmp_A, NULL, A_, q[i], ctx);
            EC_POINT_mul(group, tmp_B, NULL, B_, q[i], ctx);
            EC_POINT_add(group, sum_A, sum_A, tmp_A, ctx);
            EC_POINT_add(group, sum_B, sum_B, tmp_B, ctx);
            EC_POINT_free(tmp_A);
            EC_POINT_free(tmp_B);
        } else {
            EC_POINT *tmp_A = EC_POINT_new(group), *tmp_B = EC_POINT_new(group);
            EC_POINT_mul(group, tmp_A, NULL, g_, q[i], ctx);
            EC_POINT_mul(group, tmp_B, NULL, g_x, q[i], ctx);
            EC_POINT_add(group, sum_A, sum_A, tmp_A, ctx);
            EC_POINT_add(group, sum_B, sum_B, tmp_B, ctx);
            EC_POINT_free(tmp_A);
            EC_POINT_free(tmp_B);
        }
    }

    EC_POINT *t = EC_POINT_new(group); 
    BIGNUM *e = BN_new(), *z = BN_new();
    if (party == prover) {
        BIGNUM *k_ = BN_new();
        BN_rand(k_, 256, -1, 0);  
        EC_POINT_mul(group, t, NULL, sum_A, k_, ctx);
        send_EC_point(group, t, ios);
        receive_bn(e, ios);
        BN_mul(z, e, x, ctx);
        BN_add(z, k_, z);
        BN_mod(z, z, ORDER, ctx);
        send_bn(z, ios);

        BN_free(k_);
    } else {
        receive_EC_point(group, t, ios);
        BN_rand(e, 256, -1, 0);
        send_bn(e, ios);
        receive_bn(z, ios);
    }


    EC_POINT_mul(group, sum_A, NULL, sum_A, z, ctx);
    EC_POINT_mul(group, sum_B, NULL, sum_B, e, ctx);
    EC_POINT_add(group, sum_B, sum_B, t, ctx);
    int result = EC_POINT_cmp(group, sum_A, sum_B, ctx);
    
    EC_POINT_free(A_);
    EC_POINT_free(B_);
    EC_POINT_free(sum_A);
    EC_POINT_free(sum_B);
    EC_POINT_free(t);
    BN_free(z);
    BN_free(e);
    BN_free(ORDER);
    EVP_cleanup();
    return result;
}

