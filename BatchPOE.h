#include "util.h"
// #include <fstream>

int BatchPOE(NetIO** ios, int party, int prover, EC_GROUP *group, EC_POINT *A[], EC_POINT *B[], BIGNUM *x, EC_POINT *g_, EC_POINT *g_x, int length, BN_CTX *ctx) {
    unsigned char seed_bytes[16];
    BIGNUM *ORDER = BN_new();
    EC_GROUP_get_order(group, ORDER, ctx);
    EC_POINT *sum_A = EC_POINT_new(group); 
    EC_POINT *sum_B = EC_POINT_new(group); 
    EC_POINT *A_ = EC_POINT_new(group); 
    EC_POINT *B_ = EC_POINT_new(group); 

    if (party == prover) {
        receive_EC_point(group, A_, ios[0]);
        EC_POINT_mul(group, B_, NULL, A_, x, ctx);
        send_EC_point(group, B_, ios[0]);
        net_recv(ios[0], seed_bytes, sizeof(seed_bytes));
    } else {
        BIGNUM *ra = BN_new();
        BN_rand(ra, 256, -1, 0);
        EC_POINT_mul(group, A_, ra, NULL, NULL, ctx);
        send_EC_point(group, A_, ios[0]);
        receive_EC_point(group, B_, ios[0]);
        RAND_bytes(seed_bytes, 16);
        net_send(ios[0], seed_bytes, sizeof(seed_bytes));
        net_flush(ios[0]);
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
    ECmul_vector(group, A, tmp_veca, q, length);
    ECmul_vector(group, B, tmp_vecb, q, length);
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
        send_EC_point(group, t, ios[0]);
        receive_bn(e, ios[0]);
        BN_mul(z, e, x, ctx);
        BN_add(z, k_, z);
        BN_mod(z, z, ORDER, ctx);
        send_bn(z, ios[0]);

        BN_free(k_);
    } else {
        receive_EC_point(group, t, ios[0]);
        BN_rand(e, 256, -1, 0);
        send_bn(e, ios[0]);
        receive_bn(z, ios[0]);
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

int BatchPOE(NetIO** ios, int party, int prover, EC_GROUP *group, EC_POINT *A[], EC_POINT *B[], EC_POINT *C[], BIGNUM *x, BIGNUM *y, EC_POINT *g_, EC_POINT *h_, EC_POINT *g_x, EC_POINT *h_y, int length, BN_CTX *ctx) {
    unsigned char seed_bytes[16];
    BIGNUM *ORDER = BN_new();
    EC_GROUP_get_order(group, ORDER, ctx);
    EC_POINT *sum_A = EC_POINT_new(group); 
    EC_POINT *sum_B = EC_POINT_new(group); 
    EC_POINT *sum_C = EC_POINT_new(group); 
    EC_POINT *A_ = EC_POINT_new(group); 
    EC_POINT *B_ = EC_POINT_new(group); 
    EC_POINT *C_ = EC_POINT_new(group); 

    if (party == prover) {
        EC_POINT *tmp = EC_POINT_new(group);
        receive_EC_point(group, A_, ios[0]);
        receive_EC_point(group, B_, ios[0]);
        EC_POINT_mul(group, C_, NULL, A_, x, ctx);
        EC_POINT_mul(group, tmp, NULL, B_, y, ctx);
        EC_POINT_add(group, C_, tmp, C_, ctx);
        send_EC_point(group, C_, ios[0]);
        net_recv(ios[0], seed_bytes, sizeof(seed_bytes));
    } else {
        BIGNUM *ra = BN_new(), *rb = BN_new();
        BN_rand(ra, 256, -1, 0);
        BN_rand(rb, 256, -1, 0);
        EC_POINT_mul(group, A_, ra, NULL, NULL, ctx);
        EC_POINT_mul(group, B_, rb, NULL, NULL, ctx);
        send_EC_point(group, A_, ios[0]);
        send_EC_point(group, B_, ios[0]);
        receive_EC_point(group, C_, ios[0]);
        RAND_bytes(seed_bytes, 16);
        net_send(ios[0], seed_bytes, sizeof(seed_bytes));
        net_flush(ios[0]);
    }
    PRG *prg = new PRG(seed_bytes);
    EC_POINT **tmp_veca = (EC_POINT **)malloc(length * sizeof(EC_POINT *));
    EC_POINT **tmp_vecb = (EC_POINT **)malloc(length * sizeof(EC_POINT *));
    EC_POINT **tmp_vecc = (EC_POINT **)malloc(length * sizeof(EC_POINT *));
    BIGNUM **q = (BIGNUM **)malloc((length+2) * sizeof(BIGNUM *));
    for (int i = 0; i < length+2; i++) {
        unsigned char q_[32];
        prg->random_data(q_, sizeof(q_));
        q[i] = BN_bin2bn(q_, sizeof(q_), NULL);
        if (i < length) {
            tmp_veca[i] = EC_POINT_new(group);
            tmp_vecb[i] = EC_POINT_new(group);
            tmp_vecc[i] = EC_POINT_new(group);
        }
    }
    ECmul_vector(group, A, tmp_veca, q, length);
    ECmul_vector(group, B, tmp_vecb, q, length);
    ECmul_vector(group, C, tmp_vecc, q, length);
    for (int i = 0; i < length+2; i++) {
        if (i < length) {
            EC_POINT_add(group, sum_A, sum_A, tmp_veca[i], ctx);
            EC_POINT_add(group, sum_B, sum_B, tmp_vecb[i], ctx);
            EC_POINT_add(group, sum_C, sum_C, tmp_vecc[i], ctx);
        } else if (i == length) {
            EC_POINT *tmp_A = EC_POINT_new(group), *tmp_B = EC_POINT_new(group), *tmp_C = EC_POINT_new(group);
            EC_POINT_mul(group, tmp_A, NULL, A_, q[i], ctx);
            EC_POINT_mul(group, tmp_B, NULL, B_, q[i], ctx);
            EC_POINT_mul(group, tmp_C, NULL, C_, q[i], ctx);
            EC_POINT_add(group, sum_A, sum_A, tmp_A, ctx);
            EC_POINT_add(group, sum_B, sum_B, tmp_B, ctx);
            EC_POINT_add(group, sum_C, sum_C, tmp_C, ctx);
            EC_POINT_free(tmp_A);
            EC_POINT_free(tmp_B);
            EC_POINT_free(tmp_C);
        } else {
            EC_POINT *tmp_A = EC_POINT_new(group), *tmp_B = EC_POINT_new(group), *tmp_C = EC_POINT_new(group);
            EC_POINT_mul(group, tmp_A, NULL, g_, q[i], ctx);
            EC_POINT_mul(group, tmp_B, NULL, h_, q[i], ctx); 
            EC_POINT_add(group, tmp_C, g_x, h_y, ctx);
            EC_POINT_mul(group, tmp_C, NULL, tmp_C, q[i], ctx);
            EC_POINT_add(group, sum_A, sum_A, tmp_A, ctx);
            EC_POINT_add(group, sum_B, sum_B, tmp_B, ctx);
            EC_POINT_add(group, sum_C, sum_C, tmp_C, ctx);
            EC_POINT_free(tmp_A);
            EC_POINT_free(tmp_B);
            EC_POINT_free(tmp_C);
        }
    }

    EC_POINT *t = EC_POINT_new(group); 
    BIGNUM *e = BN_new(), *z1 = BN_new(), *z2 = BN_new();
    if (party == prover) {
        BIGNUM *k1 = BN_new(), *k2 = BN_new();
        EC_POINT *tmp = EC_POINT_new(group);
        BN_rand(k1, 256, -1, 0);  
        BN_rand(k2, 256, -1, 0);  
        EC_POINT_mul(group, t, NULL, sum_A, k1, ctx);
        EC_POINT_mul(group, tmp, NULL, sum_B, k2, ctx);
        EC_POINT_add(group, t, t, tmp, ctx);
        send_EC_point(group, t, ios[0]);
        receive_bn(e, ios[0]);
        BN_mul(z1, e, x, ctx);
        BN_add(z1, k1, z1);
        BN_mod(z1, z1, ORDER, ctx);
        send_bn(z1, ios[0]);
        BN_mul(z2, e, y, ctx);
        BN_add(z2, k2, z2);
        BN_mod(z2, z2, ORDER, ctx);
        send_bn(z2, ios[0]);

        BN_free(k1);
        BN_free(k2);
    } else {
        receive_EC_point(group, t, ios[0]);
        BN_rand(e, 256, -1, 0);
        send_bn(e, ios[0]);
        receive_bn(z1, ios[0]);
        receive_bn(z2, ios[0]);
    }


    EC_POINT_mul(group, sum_A, NULL, sum_A, z1, ctx);
    EC_POINT_mul(group, sum_B, NULL, sum_B, z2, ctx);
    EC_POINT_add(group, sum_B, sum_A, sum_B, ctx);
    EC_POINT_mul(group, sum_C, NULL, sum_C, e, ctx);
    EC_POINT_add(group, sum_C, sum_C, t, ctx);
    int result = EC_POINT_cmp(group, sum_C, sum_B, ctx);
    
    
    EC_POINT_free(A_);
    EC_POINT_free(B_);
    EC_POINT_free(sum_A);
    EC_POINT_free(sum_B);
    EC_POINT_free(t);
    BN_free(z1);
    BN_free(z2);
    BN_free(e);
    BN_free(ORDER);
    EVP_cleanup();
    return result;
}

