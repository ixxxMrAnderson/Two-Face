#include "util.h"

class Request {
    public:
        BIGNUM *sk_a, *sk_b, *xi_a, *xi_b;  
        EC_POINT *g_a, *g_b, *g_skxia, *g_skxib, *g_xia, *g_xib;
        BN_CTX *ctx;
        PRG *prg;
        int seed_a, seed_b;
        unsigned char seed_[16];
    
        Request(BIGNUM *sk_a, BIGNUM *sk_b, BIGNUM *xi_a, BIGNUM *xi_b, EC_POINT *g_a, EC_POINT *g_b, EC_POINT *g_skxia, EC_POINT *g_skxib, EC_POINT *g_xia, EC_POINT *g_xib, BN_CTX *ctx, PRG *prg, unsigned char *seed_, int seed_a, int seed_b) {
            this->sk_a = sk_a;
            this->sk_b = sk_b;
            this->xi_a = xi_a;
            this->xi_b = xi_b;
            this->g_a = g_a;
            this->g_b = g_b;
            this->g_skxia = g_skxia;
            this->g_skxib = g_skxib;
            this->g_xia = g_xia;
            this->g_xib = g_xib;
            this->ctx = ctx;
            this->prg = prg;
            memcpy(this->seed_, seed_, 16);
            this->seed_a = seed_a;
            this->seed_b = seed_b;
        }
    
        ~Request() {
            BN_free(sk_a);
            BN_free(sk_b);
            BN_free(xi_a);
            BN_free(xi_b);
            EC_POINT_free(g_a);
            EC_POINT_free(g_b);
            EC_POINT_free(g_xia);
            EC_POINT_free(g_xib);
            EC_POINT_free(g_skxia);
            EC_POINT_free(g_skxib);
        }
};


void run_request(EC_GROUP *group, NetIO *sa, NetIO *sb, std::string party_name, Request *&R, BIGNUM *sk_a, BIGNUM *sk_b, BN_CTX *ctx, PRG *prg) {
    BIGNUM *xi_a = BN_new(), *xi_b = BN_new(), *skxi_a = BN_new(), *skxi_b = BN_new();
    EC_POINT *g_a = EC_POINT_new(group), *g_b = EC_POINT_new(group), *g_skxia = EC_POINT_new(group), *g_skxib = EC_POINT_new(group), *g_xia = EC_POINT_new(group), *g_xib = EC_POINT_new(group);
    unsigned char seed_[16] = {0};
    int seed_a = 0, seed_b = 0;
    if (party_name == "C") {
        random_BN(prg, xi_a);
        random_BN(prg, xi_b);
        send_bn(xi_a, sa);
        send_bn(xi_b, sb);
        send_bn(sk_a, sa);
        send_bn(sk_b, sb);
        BIGNUM *r = BN_new();
        random_BN(prg, r);
        EC_POINT_mul(group, g_a, r, NULL, NULL, ctx);
        random_BN(prg, r);
        EC_POINT_mul(group, g_b, r, NULL, NULL, ctx);
        BN_free(r);
        BIGNUM *ORDER = BN_new();
        EC_GROUP_get_order(group, ORDER, ctx);
        BN_mul(skxi_a, sk_a, xi_a, ctx);
        BN_mod(skxi_a, skxi_a, ORDER, ctx);
        BN_mul(skxi_b, sk_b, xi_b, ctx);
        BN_mod(skxi_b, skxi_b, ORDER, ctx);
        BN_free(ORDER);
        EC_POINT_mul(group, g_xia, NULL, g_a, xi_a, ctx);
        EC_POINT_mul(group, g_xib, NULL, g_b, xi_b, ctx);
        EC_POINT_mul(group, g_skxia, NULL, g_a, skxi_a, ctx);
        EC_POINT_mul(group, g_skxib, NULL, g_b, skxi_b, ctx);
        // prg->random_data(seed_, 16);
        send_EC_point(group, g_a, sa);
        send_EC_point(group, g_a, sb);
        send_EC_point(group, g_b, sa);
        send_EC_point(group, g_b, sb);
        send_EC_point(group, g_xia, sa);
        send_EC_point(group, g_xia, sb);
        send_EC_point(group, g_xib, sa);
        send_EC_point(group, g_xib, sb);
        send_EC_point(group, g_skxia, sa);
        send_EC_point(group, g_skxia, sb);
        send_EC_point(group, g_skxib, sa);
        send_EC_point(group, g_skxib, sb);
        sa->send_data(seed_, sizeof(seed_));
        sa->send_data(&seed_a, sizeof(seed_a));
        sa->flush();
        sb->send_data(seed_, sizeof(seed_));
        sb->send_data(&seed_b, sizeof(seed_b));
        sb->flush();
    } else if (party_name == "Sa") {
        receive_bn(xi_a, sa);
        receive_bn(sk_a, sa);
        receive_EC_point(group, g_a, sa);
        receive_EC_point(group, g_b, sa);
        receive_EC_point(group, g_xia, sa);
        receive_EC_point(group, g_xib, sa);
        receive_EC_point(group, g_skxia, sa);
        receive_EC_point(group, g_skxib, sa);
        sa->recv_data(seed_, sizeof(seed_));
        sa->recv_data(&seed_a, sizeof(seed_a));
    } else {
        receive_bn(xi_b, sb);
        receive_bn(sk_b, sb);
        receive_EC_point(group, g_a, sb);
        receive_EC_point(group, g_b, sb);
        receive_EC_point(group, g_xia, sb);
        receive_EC_point(group, g_xib, sb);
        receive_EC_point(group, g_skxia, sb);
        receive_EC_point(group, g_skxib, sb);
        sb->recv_data(seed_, sizeof(seed_));
        sb->recv_data(&seed_b, sizeof(seed_b));
    }

    R = new Request(sk_a, sk_b, xi_a, xi_b, g_a, g_b, g_skxia, g_skxib, g_xia, g_xib, ctx, prg, seed_, seed_a, seed_b);
    BN_free(skxi_a);
    BN_free(skxi_b);
}