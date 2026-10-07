#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "emp-tool/io/net_io_channel.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <set>
#include <algorithm>
#include <thread>
#include "net.h"

#define N 524288
#define P 50
int thread_num = 1;
std::string sa_ip = "127.0.0.1";
std::string sb_ip = "127.0.0.1";

#define logM 13
#define M 1024
#define k 4

using namespace emp;


enum {
    TAG_A = 1,
    TAG_GAMMA_A,
    TAG_B,
    TAG_GAMMA_B,
    TAG_ROUND = 16  // + 4 * round + {0, 1: first sender's two vectors; 2, 3: second sender's}
};

// Orders serialized points by x-coordinate.
struct PointBytesLess {
    bool operator()(const unsigned char* p1, const unsigned char* p2) const {
        return memcmp(p1, p2, 32) < 0;
    }
};

void ECmul_single(const EC_GROUP* group, EC_POINT* A[], EC_POINT* B[], const BIGNUM* x, size_t length) {
    parallel_for(*g_pool, length, [=](size_t begin, size_t end) {
        BN_CTX* ctx = BN_CTX_new();
        for (size_t i = begin; i < end; ++i) EC_POINT_mul(group, B[i], nullptr, A[i], x, ctx);
        BN_CTX_free(ctx);
    });
}

void ECmul_vector(const EC_GROUP* group, EC_POINT* A[], EC_POINT* B[], BIGNUM* x[], size_t length) {
    parallel_for(*g_pool, length, [=](size_t begin, size_t end) {
        BN_CTX* ctx = BN_CTX_new();
        for (size_t i = begin; i < end; ++i) EC_POINT_mul(group, B[i], nullptr, A[i], x[i], ctx);
        BN_CTX_free(ctx);
    });
}

void setup_netio(std::string party, NetIO **ss, NetIO *&sa, NetIO *&sb, int port) {
    // printf("in setup\n");
    if (party == "Sa") {
        sa = new NetIO(nullptr, port + 1, true);
        ss[0] = new NetIO(sb_ip.c_str(), port, true);
    } else if (party == "Sb") {
        sb = new NetIO(nullptr, port + 2, true);
        ss[0] = new NetIO(nullptr, port, true);
    } else {
        sa = new NetIO(sa_ip.c_str(), port + 1, true);
        sb = new NetIO(sb_ip.c_str(), port + 2, true);
    }
    if (ss[0]) set_timeout(ss[0]);
    if (sa) set_timeout(sa);
    if (sb) set_timeout(sb);
    printf("setup finished\n");
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
    
    net_send(ios, &low, sizeof(__uint128_t ));
    net_send(ios, &high, sizeof(__uint128_t ));
    net_flush(ios);
}

void receive_bn(BIGNUM *&bn, NetIO* ios) {
    __uint128_t low, high;
    net_recv(ios, &low, sizeof(__uint128_t ));
    net_recv(ios, &high, sizeof(__uint128_t ));
    
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

void point_to_bytes(const EC_GROUP *group, const EC_POINT *point, unsigned char *out, BN_CTX *ctx) {
    unsigned char buf[65];
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, 65, ctx) != 65) protocol_abort("cannot serialize point");
    memcpy(out, buf + 1, POINT_BYTES);
}

void bytes_to_point(const EC_GROUP *group, EC_POINT *point, const unsigned char *in, BN_CTX *ctx) {
    unsigned char buf[65];
    buf[0] = 0x04;
    memcpy(buf + 1, in, POINT_BYTES);
    if (!EC_POINT_oct2point(group, point, buf, 65, ctx)) protocol_abort("peer sent a point that is not on the curve");
}

void decode_points(const EC_GROUP *group, EC_POINT *point[], const unsigned char *raw, size_t begin, size_t end) {
    BN_CTX *ctx = BN_CTX_new();
    for (size_t i = begin; i < end; ++i) bytes_to_point(group, point[i], raw + i * POINT_BYTES, ctx);
    BN_CTX_free(ctx);
}

// Position i on the wire carries point[sigma[i]], or point[i] when sigma is null.
void send_EC_vec(const EC_GROUP *group, EC_POINT *point[], size_t len, const int *sigma, uint32_t tag, NetIO *io) {
    send_stream(io, tag, len, [=](size_t begin, size_t end, unsigned char *out) {
        BN_CTX *ctx = BN_CTX_new();
        for (size_t i = begin; i < end; ++i) point_to_bytes(group, point[sigma ? sigma[i] : i], out + (i - begin) * POINT_BYTES, ctx);
        BN_CTX_free(ctx);
    });
}

// raw must hold len * POINT_BYTES bytes; chunks are decoded on the pool while later ones are still arriving.
void recv_EC_vec(const EC_GROUP *group, EC_POINT *point[], size_t len, uint32_t tag, NetIO *io, unsigned char *raw) {
    StreamReceiver rx(io, tag, len, raw);
    std::thread reader([&rx] { rx.read_all(); });
    rx.for_each_chunk([=](size_t begin, size_t end) { decode_points(group, point, raw, begin, end); });
    reader.join();
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

void print_ec_point(const EC_GROUP *group, const EC_POINT *point) {
    // Convert EC_POINT to a hex string
    char *hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL);
    if (hex == NULL) {
        printf("Failed to convert EC_POINT to hex\n");
        return;
    }

    printf("EC Point: %s\n", hex);
    OPENSSL_free(hex);
}

std::vector<int> random_permutation(size_t seed, int size) {
    std::vector<int> permutation(size);
    for (int i = 0; i < size; ++i) permutation[i] = i;
    std::mt19937 g(seed);
    std::shuffle(permutation.begin(), permutation.end(), g);
    return permutation;
}

#endif