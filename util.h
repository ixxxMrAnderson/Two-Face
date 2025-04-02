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

#define N 50000
#define P 50
#define logM 13
#define M (1ULL << logM)
#define k 3

using namespace emp;

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

struct ECaffinecord {
    BIGNUM *x, *y;
    ECaffinecord(BIGNUM *x=NULL, BIGNUM *y=NULL): x(x), y(y) {}
};

struct ECPointComparator {
    bool operator()(const ECaffinecord* p1, const ECaffinecord* p2) const {
        return (BN_cmp(p1->x, p2->x) < 0) || ((BN_cmp(p1->x, p2->x) == 0) && (BN_cmp(p1->y, p2->y) < 0));
    }
};

#endif