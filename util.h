#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "emp-tool/io/net_io_channel.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <set>
#include <algorithm>
#include <thread>

#define N 524288
#define P 50
#define logM 13
#define M 10322
#define k 3
int thread_num = 1;

using namespace emp;


void ECmul(const EC_GROUP* group, EC_POINT* A[], EC_POINT* B[], const BIGNUM* x, size_t length, int thread_id, int num_threads) {
    BN_CTX* ctx = BN_CTX_new();
    for (size_t i = 0; i < length; ++i) {
        if (i % num_threads != thread_id) continue;
        EC_POINT_mul(group, B[i], nullptr, A[i], x, ctx);
    }
    BN_CTX_free(ctx);
}

void ECmul_(const EC_GROUP* group, EC_POINT* A[], EC_POINT* B[], BIGNUM* x[], size_t length, int thread_id, int num_threads) {
    BN_CTX* ctx = BN_CTX_new();
    for (size_t i = 0; i < length; ++i) {
        if (i % num_threads != thread_id) continue;
        EC_POINT_mul(group, B[i], nullptr, A[i], x[i], ctx);
    }
    BN_CTX_free(ctx);
}

void ECadd_(const EC_GROUP* group, EC_POINT* A[], EC_POINT* B, size_t length, int thread_id, int num_threads) {
    BN_CTX* ctx = BN_CTX_new();
    for (size_t i = 0; i < length; ++i) {
        if (i % num_threads != thread_id) continue;
        EC_POINT_add(group, B, B, A[i], ctx);
    }
    BN_CTX_free(ctx);
}

void ECmul_single(const EC_GROUP* group, EC_POINT* A[], EC_POINT* B[], const BIGNUM* x, size_t length, int num_threads) {
    std::vector<std::thread> threads;
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back(ECmul, group, A, B, x, length, t, num_threads);
    }
    for (auto& th : threads) th.join();
}

void ECmul_vector(const EC_GROUP* group, EC_POINT* A[], EC_POINT* B[], BIGNUM* x[], size_t length, int num_threads) {
    std::vector<std::thread> threads;
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back(ECmul_, group, A, B, x, length, t, num_threads);
    }
    for (auto& th : threads) th.join();
}

void ECadd_vector(const EC_GROUP* group, EC_POINT* A[], EC_POINT* B, size_t length, int num_threads) {
    std::vector<std::thread> threads;
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back(ECadd_, group, A, B, length, t, num_threads);
    }
    for (auto& th : threads) th.join();
}

void setup_netio(std::string party, NetIO **ss, NetIO **sa, NetIO **sb, int port, int thread) {
    for (int i = 0; i < thread; ++i) {
        if (party == "Sa") {
            ss[i] = new NetIO(nullptr, port + i, true);
            sa[i] = new NetIO("10.0.0.126", port + thread + i, true);
        } else if (party == "Sb") {
            ss[i] = new NetIO("10.0.0.126", port + i, true);
            sb[i] = new NetIO(nullptr, port + 2*thread + i, true);
        } else {
            sa[i] = new NetIO(nullptr, port + thread + i, true);
            sa[i] = new NetIO("10.0.0.126", port + 2*thread + i, true);
        }
    }
}

void send_bn(BIGNUM *bn, NetIO* ios) {
    unsigned char bytes[32];
    memset(bytes, 0, 32);
    BN_bn2bin(bn, bytes + (32 - BN_num_bytes(bn)));

    __uint128_t low = 0, high = 0;
    for (int i = 0; i < 16; ++i) {
        low = (low << 8) | bytes[i];
        high = (high << 8) | bytes[i + 16];
    }
    
    ios->send_data(&low, sizeof(__uint128_t ));
    ios->send_data(&high, sizeof(__uint128_t ));
    ios->flush();
}

void receive_bn(BIGNUM *&bn, NetIO* ios) {
    __uint128_t low, high;
    ios->recv_data(&low, sizeof(__uint128_t ));
    ios->recv_data(&high, sizeof(__uint128_t ));
    
    unsigned char bytes[32];  
    memset(bytes, 0, 32); 

    for (int i = 15; i >= 0; --i) {
        bytes[i] = low & 0xFF;
        low >>= 8;
        bytes[i+16] = high & 0xFF;
        high >>= 8;
    }

    size_t length = 32;
    BN_bin2bn(bytes, length, bn);
}

void random_BN(PRG *prg, BIGNUM *&bn) {
    unsigned char buffer[32];
    prg->random_data(buffer, 32);    
    bn = BN_bin2bn(buffer, 32, nullptr);
}

void receive_EC_point(EC_GROUP *group, EC_POINT *&point, NetIO* ios) {
    BIGNUM *x = BN_new(), *y = BN_new();
    receive_bn(x, ios);
    receive_bn(y, ios);
    EC_POINT_set_affine_coordinates(group, point, x, y, NULL);
    BN_free(x);
    BN_free(y);
}

void send_EC_point(EC_GROUP *group, EC_POINT *point, NetIO *ios) {
    BIGNUM *x = BN_new(), *y = BN_new();
    EC_POINT_get_affine_coordinates(group, point, x, y, NULL);
    send_bn(x, ios);
    send_bn(y, ios);
    BN_free(x);
    BN_free(y);
}

void send_pEC_vec(EC_GROUP *group, EC_POINT *point[], int len, int *sigma, NetIO *ios) {
    __uint128_t *s = (__uint128_t*)malloc(4*len*sizeof(__uint128_t));
    BN_CTX *ctx = BN_CTX_new();
    for (int i = 0; i < len; ++i) {
        unsigned char buf[65];
        EC_POINT_point2oct(group, point[sigma[i]], POINT_CONVERSION_UNCOMPRESSED, buf, 65, ctx);
        memcpy(&s[4*i], buf + 1, 64); 
    }
    ios->send_data(s, 4*len*sizeof(__uint128_t ));
    ios->flush();
}
void send_EC_vec(EC_GROUP *group, EC_POINT *point[], int len, NetIO *ios) {
    __uint128_t *s = (__uint128_t*)malloc(4*len*sizeof(__uint128_t));
    BN_CTX *ctx = BN_CTX_new();
    for (int i = 0; i < len; ++i) {
        unsigned char buf[65];
        EC_POINT_point2oct(group, point[i], POINT_CONVERSION_UNCOMPRESSED, buf, 65, ctx);
        memcpy(&s[4*i], buf + 1, 64); 
    }
    ios->send_data(s, 4*len*sizeof(__uint128_t ));
    ios->flush();
}

void recv_EC_vec(EC_GROUP *group, EC_POINT *point[], int len, NetIO *ios) {
    __uint128_t *s = (__uint128_t*)malloc(4*len*sizeof(__uint128_t));
    BN_CTX *ctx = BN_CTX_new();
    ios->recv_data(s, 4*len*sizeof(__uint128_t ));
    for (int i = 0; i < len; ++i) {
        unsigned char buf[65];
        buf[0] = 0x04;
        memcpy(buf + 1,  &s[4*i], 16);
        memcpy(buf + 17, &s[4*i+1], 16);
        memcpy(buf + 33, &s[4*i+2], 16);
        memcpy(buf + 49, &s[4*i+3], 16);
        EC_POINT_oct2point(group, point[i], buf, 65, ctx);
    }
}

void print_BN(BIGNUM *bn) {
    BIO *bio = BIO_new(BIO_s_mem());
    BN_print(bio, bn);
    char buffer[256];
    int bytesRead = BIO_read(bio, buffer, sizeof(buffer) - 1);
    if (bytesRead > 0) {
        buffer[bytesRead] = '\0';  // Null-terminate the string
        std::cout << "print bn: " << buffer << std::endl;
    }
}

std::vector<int> random_permutation(size_t seed, int size) {
    std::vector<int> permutation(size);
    for (int i = 0; i < size; ++i) permutation[i] = i;
    std::mt19937 g(seed);
    std::shuffle(permutation.begin(), permutation.end(), g);
    return permutation;
}

struct ECoct {
    __uint128_t *s;
    ECoct() {
        s = (__uint128_t*)malloc(4*sizeof(__uint128_t));
    }
};

struct ECPointComparator {
    bool operator()(const ECoct* p1, const ECoct* p2) const {
        return (p1->s[0]<p2->s[0])||((p1->s[0]==p2->s[0])&&(p1->s[1]<p2->s[1]));
    }
};

#endif