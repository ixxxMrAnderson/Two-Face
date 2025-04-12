#include "BatchPOE.h"
#include "run_request.cpp"

void run_receive(EC_GROUP *group, NetIO **ios, NetIO *sa, NetIO *sb, std::string party_name, EC_POINT *c1[], EC_POINT *c2[], Request *R) {
    int party = ALICE;
    if (party_name == "Sb") party = BOB;
    struct timespec startec_mul, endec_mul, startt, endt, startcmp, endcmp, start, end;
    double eec, et, ecmp;
    clock_gettime(CLOCK_MONOTONIC, &start);
    BIGNUM *sk_a = R->sk_a, *sk_b = R->sk_b, *xi_a = R->xi_a, *xi_b = R->xi_b, *ORDER = BN_new();
    BN_CTX *ctx = R->ctx;
    EC_POINT *g_a = R->g_a, *g_b = R->g_b, *g_skxia = R->g_skxia, *g_skxib = R->g_skxib, *g_xia = R->g_xia, *g_xib = R->g_xib;
    int seed_a = R->seed_a, seed_b = R->seed_b;
    unsigned char seed_[16];
    memcpy(seed_, R->seed_, 16);
    EC_GROUP_get_order(group, ORDER, ctx);

    EC_POINT **A_ = (EC_POINT **)malloc(N * sizeof(EC_POINT *));
    EC_POINT **B_ = (EC_POINT **)malloc(N * sizeof(EC_POINT *));
    EC_POINT **gamma = (EC_POINT **)malloc(M * sizeof(EC_POINT *));
    EC_POINT **gamma_A = (EC_POINT **)malloc(M * sizeof(EC_POINT *));
    EC_POINT **gamma_B = (EC_POINT **)malloc(M * sizeof(EC_POINT *));
    
    BIGNUM *skxi_a = BN_new(), *skxi_b = BN_new();
    if (party == ALICE) {
        BN_mul(skxi_a, sk_a, xi_a, ctx);
        BN_mod(skxi_a, skxi_a, ORDER, ctx);
    } else {
        BN_mul(skxi_b, sk_b, xi_b, ctx);
        BN_mod(skxi_b, skxi_b, ORDER, ctx);
    }

    for (int i = 0; i < N; ++i) {
        A_[i] = EC_POINT_new(group);
        B_[i] = EC_POINT_new(group);
    }

    clock_gettime(CLOCK_MONOTONIC, &startec_mul);
    if (party == ALICE) ECmul_single(std::ref(group), c1, A_, std::ref(skxi_a), N, thread_num);
    else ECmul_single(std::ref(group), c1, B_, std::ref(skxi_b), N, thread_num);

    PRG *prg_ = new PRG(seed_);
    for (int i = 0; i < M; ++i) {
        gamma_A[i] = EC_POINT_new(group);
        gamma_B[i] = EC_POINT_new(group);
        gamma[i] = EC_POINT_new(group);
        BIGNUM *bn = BN_new();
        random_BN(prg_, bn);
        EC_POINT_mul(group, gamma[i], bn, NULL, NULL, ctx);
        BN_free(bn);
    }


    if (party == ALICE) ECmul_single(std::ref(group), gamma, gamma_A, std::ref(xi_a), M, thread_num);
    else ECmul_single(std::ref(group), gamma, gamma_B, std::ref(xi_b), M, thread_num);
    clock_gettime(CLOCK_MONOTONIC, &endec_mul);
    eec = endec_mul.tv_sec - startec_mul.tv_sec;
    eec += (endec_mul.tv_nsec - startec_mul.tv_nsec)/1000000000.0;


    // printf("  S_a ----A_----> S_b \n");
    clock_gettime(CLOCK_MONOTONIC, &startt);
    if (party == ALICE) send_EC_vec(group, A_, N, ios);
    else recv_EC_vec(group, A_, N, ios);
    clock_gettime(CLOCK_MONOTONIC, &endt);
    et = (endt.tv_sec - startt.tv_sec)*2;
    et += (endt.tv_nsec - startt.tv_nsec)*2/1000000000.0;
    clock_gettime(CLOCK_MONOTONIC, &startec_mul);
    if (BatchPOE(ios, party, ALICE, group, c1, A_, skxi_a, g_a, g_skxia, N, ctx)) printf("N: S_b aborts.\n");
    clock_gettime(CLOCK_MONOTONIC, &endec_mul);
    eec += (endec_mul.tv_sec - startec_mul.tv_sec)*2;
    eec += (endec_mul.tv_nsec - startec_mul.tv_nsec)/1000000000.0;
    
    
    clock_gettime(CLOCK_MONOTONIC, &startt);
    if (party == ALICE) send_EC_vec(group, gamma_A, M, ios);
    else recv_EC_vec(group, gamma_A, M, ios);
    clock_gettime(CLOCK_MONOTONIC, &endt);
    et += (endt.tv_sec - startt.tv_sec)*2;
    et += (endt.tv_nsec - startt.tv_nsec)*2/1000000000.0;
    clock_gettime(CLOCK_MONOTONIC, &startec_mul);
    if (BatchPOE(ios, party, ALICE, group, gamma, gamma_A, xi_a, g_a, g_xia, M, ctx)) printf("M: S_b aborts.\n");
    clock_gettime(CLOCK_MONOTONIC, &endec_mul);
    eec += (endec_mul.tv_sec - startec_mul.tv_sec)*2;
    eec += (endec_mul.tv_nsec - startec_mul.tv_nsec)/1000000000.0;

    // printf("  S_b ----B_----> S_a \n");
    if (party == ALICE) recv_EC_vec(group, B_, N, ios);
    else send_EC_vec(group, B_, N, ios);
    if (BatchPOE(ios, party, BOB, group, c1, B_, skxi_b, g_b, g_skxib, N, ctx)) printf("N: S_a aborts.\n");
    if (party == ALICE) recv_EC_vec(group, gamma_B, M, ios);
    else send_EC_vec(group, gamma_B, M, ios);
    if (BatchPOE(ios, party, BOB, group, gamma, gamma_B, xi_b, g_b, g_xib, M, ctx)) printf("M: S_a aborts.\n");

    EC_POINT **Ha = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    EC_POINT **Hb = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    EC_POINT **Ka = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    EC_POINT **Kb = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    EC_POINT **tmp_vec = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    ECoct **EC_recv = (ECoct **)malloc((N+M) * sizeof(ECoct *));
    
    for (int i = 0; i < N+M; ++i) {
        Ha[i] = EC_POINT_new(group);
        Hb[i] = EC_POINT_new(group);
        Ka[i] = EC_POINT_new(group);
        Kb[i] = EC_POINT_new(group);
        tmp_vec[i] = EC_POINT_new(group);
        EC_recv[i] = new ECoct();
    }

    BIGNUM *xi_inv_a = BN_new(), *xi_inv_b = BN_new();
    BN_mod_inverse(xi_inv_a, xi_a, ORDER, NULL);
    BN_mod_inverse(xi_inv_b, xi_b, ORDER, NULL);
    ecmp = 0;
    for (int j = 0; j < k; ++j){
        BIGNUM *omega_a = BN_new(), *omega_b = BN_new();
        if (party == ALICE) BN_rand(omega_a, 256, -1, 0);
        else BN_rand(omega_b, 256, -1, 0);

        clock_gettime(CLOCK_MONOTONIC, &startec_mul);
        if (party == ALICE) {
            ECmul_single(std::ref(group), B_, Ha, std::ref(omega_a), N, thread_num);
            ECmul_single(std::ref(group), c1, tmp_vec, std::ref(sk_a), N, thread_num);
            ECmul_single(std::ref(group), gamma_B, &Ha[N], std::ref(omega_a), M, thread_num);
            ECmul_single(std::ref(group), gamma, &Hb[N], std::ref(omega_a), M, thread_num);
        } else {
            ECmul_single(std::ref(group), A_, Ka, std::ref(omega_b), N, thread_num);
            ECmul_single(std::ref(group), c1, tmp_vec, std::ref(sk_b), N, thread_num);
            ECmul_single(std::ref(group), gamma_A, &Ka[N], std::ref(omega_b), M, thread_num);
            ECmul_single(std::ref(group), gamma, &Kb[N], std::ref(omega_b), M, thread_num);
        }
        
        for (int i = 0; i < N; ++i) {
            if (party == ALICE) {
                EC_POINT_invert(group, tmp_vec[i], ctx);
                EC_POINT_add(group, Hb[i], c2[i], tmp_vec[i], ctx);
            } else {
                EC_POINT_invert(group, tmp_vec[i], ctx);
                EC_POINT_add(group, Kb[i], c2[i], tmp_vec[i], ctx);
            }
        }
        std::vector<int> sigma;
        if (party == ALICE) {
            ECmul_single(std::ref(group), Hb, Hb, std::ref(omega_a), N, thread_num);
            sigma = random_permutation(seed_a, N+M);
            // printf("sigma: ");
            // for (int i = 0; i < N+M; ++i) printf("%d ", sigma[i]);
            // printf("\n");
            seed_a = sigma[0];
        } else {
            ECmul_single(std::ref(group), Kb, Kb, std::ref(omega_b), N, thread_num);
            sigma = random_permutation(seed_b, N+M);
            // printf("sigma: ");
            // for (int i = 0; i < N+M; ++i) printf("%d ", sigma[i]);
            // printf("\n");
            seed_b = sigma[0];
        }
        clock_gettime(CLOCK_MONOTONIC, &endec_mul);
        eec += (endec_mul.tv_sec - startec_mul.tv_sec);
        eec += (endec_mul.tv_nsec - startec_mul.tv_nsec)/1000000000.0;
        clock_gettime(CLOCK_MONOTONIC, &startt);
        if (party == ALICE) {
            recv_EC_vec(group, Ka, N+M, ios);
            // recv_EC_vec(group, Kb, N+M, ios);
            recv_vec(EC_recv, N+M, ios);
            send_pEC_vec(group, Ha, N+M, sigma.data(), ios);
            send_pEC_vec(group, Hb, N+M, sigma.data(), ios);
        } else {
            send_pEC_vec(group, Ka, N+M, sigma.data(), ios);
            send_pEC_vec(group, Kb, N+M, sigma.data(), ios);
            recv_EC_vec(group, Ha, N+M, ios);
            recv_vec(EC_recv, N+M, ios);
        }
        clock_gettime(CLOCK_MONOTONIC, &endt);
        et += (endt.tv_sec - startt.tv_sec);
        et += (endt.tv_nsec - startt.tv_nsec)/1000000000.0;
        clock_gettime(CLOCK_MONOTONIC, &startcmp);
        std::set<ECoct*, ECPointComparator> ECset;
        for (int i = 0; i < N+M; ++i) {
            if (ECset.find(EC_recv[i])==ECset.end()) {
                ECset.insert(EC_recv[i]);
                unsigned char buf[65];
                buf[0] = 0x04;
                memcpy(buf + 1, EC_recv[i]->s, 64);
                if (party == ALICE) EC_POINT_oct2point(group, Kb[i], buf, 65, ctx);
                else EC_POINT_oct2point(group, Hb[i], buf, 65, ctx);
            }
            else printf("Server abort\n");
        }
        clock_gettime(CLOCK_MONOTONIC, &endcmp);
        ecmp += (endcmp.tv_sec - startcmp.tv_sec);
        ecmp += (endcmp.tv_nsec - startcmp.tv_nsec)/1000000000.0;
        

        clock_gettime(CLOCK_MONOTONIC, &startec_mul);
        if (party == ALICE) {
            ECmul_single(std::ref(group), Ka, Ka, std::ref(xi_inv_a), N+M, thread_num);
        } else {
            ECmul_single(std::ref(group), Ha, Ha, std::ref(xi_inv_b), N+M, thread_num);
        }
        clock_gettime(CLOCK_MONOTONIC, &endec_mul);
        eec += (endec_mul.tv_sec - startec_mul.tv_sec);
        eec += (endec_mul.tv_nsec - startec_mul.tv_nsec)/1000000000.0;
        if (party == ALICE) {
            for (int i = 0; i < N+M; ++i) {
                if (!EC_POINT_cmp(group, Ka[i], Kb[i], ctx)) {
                    sa->send_data(&i, sizeof(i));
                    sa->flush();
                    // printf("send: %d\n", i);
                }
            }
        } else {
            for (int i = 0; i < N+M; ++i) {
                if (!EC_POINT_cmp(group, Ha[i], Hb[i], ctx)) {
                    sb->send_data(&i, sizeof(i));
                    sb->flush();
                    // printf("send: %d\n", i);
                }
            }
        }
        BN_free(omega_a);
        BN_free(omega_b);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec);
    elapsed += (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("ECmul time: %.6f seconds\n", eec); 
    printf("Trans time: %.6f seconds\n", et); 
    printf("Cmp time: %.6f seconds\n", ecmp); 
    printf("Other time: %.6f seconds\n", elapsed-eec-et-ecmp); 

    BN_free(ORDER);
    BN_free(xi_inv_a);
    BN_free(xi_inv_b);
    BN_free(skxi_a);
    BN_free(skxi_b);
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
