#include "BatchPOE.h"
#include "run_request.cpp"

// Seconds since t; also resets t to now.
double lap(struct timespec &t) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double d = (now.tv_sec - t.tv_sec) + (now.tv_nsec - t.tv_nsec) / 1000000000.0;
    t = now;
    return d;
}

void run_receive(EC_GROUP *group, NetIO **ios, NetIO *sa, NetIO *sb, std::string party_name, EC_POINT *c1[], EC_POINT *c2[], Request *R) {
    int party = ALICE;
    if (party_name == "Sb") party = BOB;
    NetIO *peer = ios[0];
    struct timespec start, phase, startcmp;
    double t_commit = 0, t_poe = 0, t_rounds = 0, ecmp = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    BIGNUM *sk_a = R->sk_a, *sk_b = R->sk_b, *xi_a = R->xi_a, *xi_b = R->xi_b, *ORDER = BN_new();
    BN_CTX *ctx = R->ctx;
    EC_POINT *g_a = R->g_a, *g_b = R->g_b, *h_a = R->h_a, *h_b = R->h_b, *h_skxia = R->h_skxia, *h_skxib = R->h_skxib, *g_xia = R->g_xia, *g_xib = R->g_xib;
    int seed_a = R->seed_a, seed_b = R->seed_b;
    unsigned char seed_[16];
    memcpy(seed_, R->seed_, 16);
    EC_GROUP_get_order(group, ORDER, ctx);

    // hash(seed_, g_a, h_a, g_b, h_b, g_xia, g_xib, h_skxia, h_skxib)
    unsigned char *buf = (unsigned char *)malloc(16+65*8);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    memcpy(buf, seed_, 16);
    EC_POINT_point2oct(group, g_a, POINT_CONVERSION_UNCOMPRESSED, &buf[16], 65, ctx);
    EC_POINT_point2oct(group, g_b, POINT_CONVERSION_UNCOMPRESSED, &buf[16+65], 65, ctx);
    EC_POINT_point2oct(group, h_a, POINT_CONVERSION_UNCOMPRESSED, &buf[16+65*2], 65, ctx);
    EC_POINT_point2oct(group, h_b, POINT_CONVERSION_UNCOMPRESSED, &buf[16+65*3], 65, ctx);
    EC_POINT_point2oct(group, g_xia, POINT_CONVERSION_UNCOMPRESSED, &buf[16+65*4], 65, ctx);
    EC_POINT_point2oct(group, g_xib, POINT_CONVERSION_UNCOMPRESSED, &buf[16+65*5], 65, ctx);
    EC_POINT_point2oct(group, h_skxia, POINT_CONVERSION_UNCOMPRESSED, &buf[16+65*6], 65, ctx);
    EC_POINT_point2oct(group, h_skxib, POINT_CONVERSION_UNCOMPRESSED, &buf[16+65*7], 65, ctx);

    SHA256((unsigned char*)buf, sizeof(buf), hash);
    if (party == ALICE) {
        net_send(ios[0], hash, 16);
        net_send(ios[0], &hash[16], 16);
        net_flush(ios[0]);
    } else {
        __uint128_t tmpa, tmpb;
        memcpy(&tmpa, hash, 16);
        net_recv(ios[0], &tmpb, 16);
        if (tmpb != tmpa) protocol_abort("setup parameters differ from Sa's");
        memcpy(&tmpa, &hash[16], 16);
        net_recv(ios[0], &tmpb, 16);
        if (tmpb != tmpa) protocol_abort("setup parameters differ from Sa's");
    }

    EC_POINT **A_ = (EC_POINT **)malloc(N * sizeof(EC_POINT *));
    EC_POINT **B_ = (EC_POINT **)malloc(N * sizeof(EC_POINT *));
    EC_POINT **R_ = (EC_POINT **)malloc(N * sizeof(EC_POINT *));
    EC_POINT **gamma = (EC_POINT **)malloc(M * sizeof(EC_POINT *));
    EC_POINT **gamma_A = (EC_POINT **)malloc(M * sizeof(EC_POINT *));
    EC_POINT **gamma_B = (EC_POINT **)malloc(M * sizeof(EC_POINT *));
    unsigned char *raw1 = (unsigned char *)malloc((size_t)(N + M) * POINT_BYTES);
    unsigned char *raw2 = (unsigned char *)malloc((size_t)(N + M) * POINT_BYTES);
    
    BIGNUM *skxi_a = BN_new(), *skxi_b = BN_new();
    if (party == ALICE) {
        BN_mul(skxi_a, sk_a, xi_a, ctx);
        BN_mod(skxi_a, skxi_a, ORDER, ctx);
    } else {
        BN_mul(skxi_b, sk_b, xi_b, ctx);
        BN_mod(skxi_b, skxi_b, ORDER, ctx);
    }
    BIGNUM *sk = (party == ALICE) ? sk_a : sk_b;
    BIGNUM *xi = (party == ALICE) ? xi_a : xi_b;
    BIGNUM *skxi = (party == ALICE) ? skxi_a : skxi_b;

    PRG *prg_ = new PRG(&seed_);
    for (int i = 0; i < N; ++i) {
        A_[i] = EC_POINT_new(group);
        B_[i] = EC_POINT_new(group);
        R_[i] = EC_POINT_new(group);
        BIGNUM *x = BN_new();
        random_BN(prg_, x);
        while (!EC_POINT_set_compressed_coordinates_GFp(group, R_[i], x, 1, ctx)) {
            random_BN(prg_, x);
        }
    }
    // printf("R_ finished\n");

    for (int i = 0; i < M; ++i) {
        gamma_A[i] = EC_POINT_new(group);
        gamma_B[i] = EC_POINT_new(group);
        gamma[i] = EC_POINT_new(group);
        BIGNUM *x = BN_new();
        random_BN(prg_, x);
        while (!EC_POINT_set_compressed_coordinates_GFp(group, gamma[i], x, 1, ctx)) {
            random_BN(prg_, x);
        }
    }
    // printf("gamma_ finished\n");

    clock_gettime(CLOCK_MONOTONIC, &phase);
    // mine[i] = xi * R_[i] + skxi * c1[i]
    EC_POINT **mine = (party == ALICE) ? A_ : B_;
    auto commit = [=](size_t i, EC_POINT *tmp, BN_CTX *bctx) {
        EC_POINT_mul(group, tmp, nullptr, R_[i], xi, bctx);
        EC_POINT_mul(group, mine[i], nullptr, c1[i], skxi, bctx);
        EC_POINT_add(group, mine[i], tmp, mine[i], bctx);
    };

    // printf("  S_a ----A_----> S_b \n");
    if (party == ALICE) {
        // Each chunk of A_ is sent as soon as it is computed.
        send_stream(peer, TAG_A, N, [=](size_t begin, size_t end, unsigned char *out) {
            BN_CTX *bctx = BN_CTX_new();
            EC_POINT *tmp = EC_POINT_new(group);
            for (size_t i = begin; i < end; ++i) {
                commit(i, tmp, bctx);
                point_to_bytes(group, A_[i], out + (i - begin) * POINT_BYTES, bctx);
            }
            EC_POINT_free(tmp);
            BN_CTX_free(bctx);
        });
        ECmul_single(group, gamma, gamma_A, xi_a, M);
    } else {
        // A_ is received in the background while B_ is computed, then decoded.
        StreamReceiver rx(peer, TAG_A, N, raw1);
        std::thread reader([&rx] { rx.read_all(); });
        parallel_for(*g_pool, N, [=](size_t begin, size_t end) {
            BN_CTX *bctx = BN_CTX_new();
            EC_POINT *tmp = EC_POINT_new(group);
            for (size_t i = begin; i < end; ++i) commit(i, tmp, bctx);
            EC_POINT_free(tmp);
            BN_CTX_free(bctx);
        });
        ECmul_single(group, gamma, gamma_B, xi_b, M);
        rx.for_each_chunk([=](size_t begin, size_t end) { decode_points(group, A_, raw1, begin, end); });
        reader.join();
    }
    t_commit += lap(phase);
    if (BatchPOE(ios, party, ALICE, group, R_, c1, A_, xi_a, skxi_a, g_a, h_a, g_xia, h_skxia, N, ctx)) protocol_abort("Sa's batch proof for A_ failed");
    t_poe += lap(phase);

    if (party == ALICE) send_EC_vec(group, gamma_A, M, nullptr, TAG_GAMMA_A, peer);
    else recv_EC_vec(group, gamma_A, M, TAG_GAMMA_A, peer, raw1);
    t_commit += lap(phase);
    if (BatchPOE(ios, party, ALICE, group, gamma, gamma_A, xi_a, g_a, g_xia, M, ctx)) protocol_abort("Sa's batch proof for gamma_A failed");
    t_poe += lap(phase);

    // // printf("  S_b ----B_----> S_a \n");
    if (party == ALICE) recv_EC_vec(group, B_, N, TAG_B, peer, raw1);
    else send_EC_vec(group, B_, N, nullptr, TAG_B, peer);
    t_commit += lap(phase);
    if (BatchPOE(ios, party, BOB, group, R_, c1, B_, xi_b, skxi_b, g_b, h_b, g_xib, h_skxib, N, ctx)) protocol_abort("Sb's batch proof for B_ failed");
    t_poe += lap(phase);
    if (party == ALICE) recv_EC_vec(group, gamma_B, M, TAG_GAMMA_B, peer, raw1);
    else send_EC_vec(group, gamma_B, M, nullptr, TAG_GAMMA_B, peer);
    t_commit += lap(phase);
    if (BatchPOE(ios, party, BOB, group, gamma, gamma_B, xi_b, g_b, g_xib, M, ctx)) protocol_abort("Sb's batch proof for gamma_B failed");
    t_poe += lap(phase);
    // return;
    EC_POINT **Ha = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    EC_POINT **Hb = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    EC_POINT **Ka = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    EC_POINT **Kb = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    
    for (int i = 0; i < N+M; ++i) {
        Ha[i] = EC_POINT_new(group);
        Hb[i] = EC_POINT_new(group);
        Ka[i] = EC_POINT_new(group);
        Kb[i] = EC_POINT_new(group);
    }

    // Sa works on (Ha, Hb) and receives (Ka, Kb); Sb the other way round.
    EC_POINT **mine1 = (party == ALICE) ? Ha : Ka, **mine2 = (party == ALICE) ? Hb : Kb;
    EC_POINT **peer1 = (party == ALICE) ? Ka : Ha, **peer2 = (party == ALICE) ? Kb : Hb;
    EC_POINT **peer_commit = (party == ALICE) ? B_ : A_, **peer_gamma = (party == ALICE) ? gamma_B : gamma_A;
    NetIO *client = (party == ALICE) ? sa : sb;
    int seed = (party == ALICE) ? seed_a : seed_b;
    BIGNUM *xi_inv = BN_new();
    BN_mod_inverse(xi_inv, xi, ORDER, ctx);
    for (int j = 0; j < k; ++j){
        BIGNUM *omega = BN_new();
        BN_rand(omega, 256, -1, 0);
        std::vector<int> sigma = random_permutation(seed, N+M);
        seed = sigma[0];
        const int *perm = sigma.data();
        uint32_t tag = TAG_ROUND + 4 * j;

        // mine1[i] = omega * B_[i] (or A_[i]), mine2[i] = omega * (c2[i] - sk * c1[i] + R_[i]);
        // the last M entries are omega * gamma_B (or gamma_A) and omega * gamma.
        auto compute = [=](size_t i, EC_POINT *tmp, BN_CTX *bctx) {
            if (i < N) {
                EC_POINT_mul(group, mine1[i], nullptr, peer_commit[i], omega, bctx);
                EC_POINT_mul(group, tmp, nullptr, c1[i], sk, bctx);
                EC_POINT_invert(group, tmp, bctx);
                EC_POINT_add(group, tmp, c2[i], tmp, bctx);
                EC_POINT_add(group, tmp, tmp, R_[i], bctx);
                EC_POINT_mul(group, mine2[i], nullptr, tmp, omega, bctx);
            } else {
                EC_POINT_mul(group, mine1[i], nullptr, peer_gamma[i - N], omega, bctx);
                EC_POINT_mul(group, mine2[i], nullptr, gamma[i - N], omega, bctx);
            }
        };
        // peer1[i] = xi^-1 * (point at position i of the peer's first vector)
        auto open1 = [=](size_t begin, size_t end) {
            BN_CTX *bctx = BN_CTX_new();
            for (size_t i = begin; i < end; ++i) {
                bytes_to_point(group, peer1[i], raw1 + i * POINT_BYTES, bctx);
                EC_POINT_mul(group, peer1[i], nullptr, peer1[i], xi_inv, bctx);
            }
            BN_CTX_free(bctx);
        };
        auto decode2 = [=](size_t begin, size_t end) { decode_points(group, peer2, raw2, begin, end); };

        StreamReceiver rx1(peer, tag + (party == ALICE ? 0 : 2), N+M, raw1);
        StreamReceiver rx2(peer, tag + (party == ALICE ? 1 : 3), N+M, raw2);
        if (party == ALICE) {
            // Sb's vectors arrive in the background while ours are computed.
            std::thread reader([&] { rx1.read_all(); rx2.read_all(); });
            parallel_for(*g_pool, N+M, [=](size_t begin, size_t end) {
                BN_CTX *bctx = BN_CTX_new();
                EC_POINT *tmp = EC_POINT_new(group);
                for (size_t i = begin; i < end; ++i) compute(i, tmp, bctx);
                EC_POINT_free(tmp);
                BN_CTX_free(bctx);
            });
            // As in the protocol, Sa replies only after it has all of Sb's vectors.
            reader.join();
            send_EC_vec(group, mine1, N+M, perm, tag + 2, peer);
            send_EC_vec(group, mine2, N+M, perm, tag + 3, peer);
            rx1.for_each_chunk(open1);
            rx2.for_each_chunk(decode2);
        } else {
            // Sb sends each chunk of Ka as soon as it is computed (Kb is computed in the same pass).
            send_stream(peer, tag, N+M, [=](size_t begin, size_t end, unsigned char *out) {
                BN_CTX *bctx = BN_CTX_new();
                EC_POINT *tmp = EC_POINT_new(group);
                for (size_t i = begin; i < end; ++i) {
                    compute(perm[i], tmp, bctx);
                    point_to_bytes(group, mine1[perm[i]], out + (i - begin) * POINT_BYTES, bctx);
                }
                EC_POINT_free(tmp);
                BN_CTX_free(bctx);
            });
            send_EC_vec(group, mine2, N+M, perm, tag + 1, peer);
            // Sa's chunks are opened as they arrive.
            std::thread reader([&] { rx1.read_all(); rx2.read_all(); });
            rx1.for_each_chunk(open1);
            rx2.for_each_chunk(decode2);
            reader.join();
        }

        clock_gettime(CLOCK_MONOTONIC, &startcmp);
        std::set<const unsigned char*, PointBytesLess> ECset;
        for (int i = 0; i < N+M; ++i) {
            if (!ECset.insert(raw2 + (size_t)i * POINT_BYTES).second) protocol_abort("the other server's shuffled vector repeats a point");
        }
        ecmp += lap(startcmp);

        for (int i = 0; i < N+M; ++i) {
            if (!EC_POINT_cmp(group, peer1[i], peer2[i], ctx)) {
                net_send(client, &i, sizeof(i));
                net_flush(client);
            }
        }
        BN_free(omega);
        t_rounds += lap(phase);
    }

    double elapsed = lap(start);
    // Computing and sending overlap, so times are per phase, not split into EC and transfer.
    printf("Commit time: %.6f seconds\n", t_commit); 
    printf("Proof time: %.6f seconds\n", t_poe); 
    printf("Round time: %.6f seconds\n", t_rounds); 
    printf("Cmp time (part of rounds): %.6f seconds\n", ecmp); 
    printf("Other time: %.6f seconds\n", elapsed-t_commit-t_poe-t_rounds); 
    printf("Total time: %.6f seconds\n", elapsed); 

    BN_free(ORDER);
    BN_free(xi_inv);
    BN_free(skxi_a);
    BN_free(skxi_b);
    free(raw1);
    free(raw2);
    for (int i = 0; i < N; ++i){
        EC_POINT_free(A_[i]);
        EC_POINT_free(B_[i]);
        EC_POINT_free(Ha[i]);
        EC_POINT_free(Hb[i]);
        EC_POINT_free(Ka[i]);
        EC_POINT_free(Kb[i]);
    }
    for (int i = 0; i < M; ++i){
        EC_POINT_free(gamma[i]);
        EC_POINT_free(gamma_A[i]);
        EC_POINT_free(gamma_B[i]);
    }
}
