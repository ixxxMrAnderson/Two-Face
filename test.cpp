#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>

constexpr int NUM_OPS = 1 << 15;
constexpr int NUM_THREADS = 4;

// Function to perform EC multiplications
void ec_mul_task(int ops_per_thread, EC_GROUP* group, BN_CTX* ctx) {
    BIGNUM* scalar = BN_new();
    EC_POINT* result = EC_POINT_new(group);
    for (int i = 0; i < ops_per_thread; ++i) {
        BN_set_word(scalar, i + 1);
        EC_POINT_mul(group, result, scalar, NULL, NULL, ctx);
    }
    EC_POINT_free(result);
    BN_free(scalar);
}

// Single-threaded benchmark
void benchmark_single_thread(EC_GROUP* group, BN_CTX* ctx) {
    std::cout << "Running single-threaded test...\n";
    auto start = std::chrono::high_resolution_clock::now();
    ec_mul_task(NUM_OPS, group, ctx);
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Single-thread time: "
              << std::chrono::duration<double>(end - start).count()
              << " seconds\n";
}

// Multi-threaded benchmark
void benchmark_multi_thread(EC_GROUP* group, BN_CTX* ctx) {
    std::cout << "Running multi-threaded test with " << NUM_THREADS << " threads...\n";

    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::thread> threads;

    for (int i = 0; i < NUM_THREADS; ++i) {
        threads.emplace_back([=]() {
            BN_CTX* thread_ctx = BN_CTX_new();
            ec_mul_task(NUM_OPS / NUM_THREADS, group, thread_ctx);
            BN_CTX_free(thread_ctx);
        });
    }

    for (auto& t : threads) t.join();

    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Multi-thread time: "
              << std::chrono::duration<double>(end - start).count()
              << " seconds\n";
}

int main() {
    OpenSSL_add_all_algorithms();
    BN_CTX* ctx = BN_CTX_new();

    // Use curve secp256k1 (or change to NID_X9_62_prime256v1 if needed)
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    benchmark_single_thread(group, ctx);
    benchmark_multi_thread(group, ctx);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    return 0;
}
