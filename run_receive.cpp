#include "BatchPOE.h"
#include "run_request.cpp"

void run_receive(EC_GROUP *group, NetIO *ios, NetIO *sa, NetIO *sb, std::string party_name, EC_POINT *c1[], EC_POINT *c2[], Request *R) {
    int party = ALICE;
    if (party_name == "Sb") party = BOB;
    BIGNUM *sk_a = R->sk_a, *sk_b = R->sk_b, *xi_a = R->xi_a, *xi_b = R->xi_b, *ORDER = BN_new();
    BN_CTX *ctx = R->ctx;
    EC_POINT *g_a = R->g_a, *g_b = R->g_b, *g_skxia = R->g_skxia, *g_skxib = R->g_skxib, *g_xia = R->g_xia, *g_xib = R->g_xib;
    int seed_a = R->seed_a, seed_b = R->seed_b;
    unsigned char seed_[16];
    memcpy(seed_, R->seed_, 16);
    EC_GROUP_get_order(group, ORDER, ctx);
    clock_t start = clock();

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
    struct timespec startt, finish;
    double elapsed;

    clock_gettime(CLOCK_MONOTONIC, &startt);
    for (int i = 0; i < N; ++i) {
        A_[i] = EC_POINT_new(group);
        B_[i] = EC_POINT_new(group);
    }

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

    clock_t de_ = clock();
    double de_time = ((double)(de_ - start)) / CLOCKS_PER_SEC;
    printf("Decrypt time: %.6f seconds\n", de_time); 


    printf("  S_a ----A_----> S_b \n");
    for (int i = 0; i < N; ++i) {
        if (party == ALICE) send_EC_point(group, A_[i], ios);
        else receive_EC_point(group, A_[i], ios);
    }
    if (BatchPOE(ios, party, ALICE, group, c1, A_, skxi_a, g_a, g_skxia, N, ctx)) printf("N: S_b aborts.\n");
    for (int i = 0; i < M; ++i) {
        if (party == ALICE) send_EC_point(group, gamma_A[i], ios);
        else receive_EC_point(group, gamma_A[i], ios);
    }
    if (BatchPOE(ios, party, ALICE, group, gamma, gamma_A, xi_a, g_a, g_xia, M, ctx)) printf("M: S_b aborts.\n");


    printf("  S_b ----B_----> S_a \n");
    for (int i = 0; i < N; ++i) {
        if (party == ALICE) receive_EC_point(group, B_[i], ios);
        else send_EC_point(group, B_[i], ios);
    }
    if (BatchPOE(ios, party, BOB, group, c1, B_, skxi_b, g_b, g_skxib, N, ctx)) printf("N: S_a aborts.\n");
    for (int i = 0; i < M; ++i) {
        if (party == ALICE) receive_EC_point(group, gamma_B[i], ios);
        else send_EC_point(group, gamma_B[i], ios);
    }
    if (BatchPOE(ios, party, BOB, group, gamma, gamma_B, xi_b, g_b, g_xib, M, ctx)) printf("M: S_a aborts.\n");

    clock_t mid_ = clock();
    double prove_time = ((double)(mid_ - de_)) / CLOCKS_PER_SEC;
    printf("Proof time: %.6f seconds\n", prove_time); // 5N+6M ~15s w N=100000

    EC_POINT **Ha = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    EC_POINT **Hb = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    EC_POINT **Ka = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    EC_POINT **Kb = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    EC_POINT **tmp_vec = (EC_POINT **)malloc((N+M) * sizeof(EC_POINT *));
    ECaffinecord **EC_recva = (ECaffinecord **)malloc((N+M) * sizeof(ECaffinecord *));
    ECaffinecord **EC_recvb = (ECaffinecord **)malloc((N+M) * sizeof(ECaffinecord *));
    
    for (int i = 0; i < N+M; ++i) {
        Ha[i] = EC_POINT_new(group);
        Hb[i] = EC_POINT_new(group);
        Ka[i] = EC_POINT_new(group);
        Kb[i] = EC_POINT_new(group);
        tmp_vec[i] = EC_POINT_new(group);
        EC_recva[i] = new ECaffinecord();
        EC_recvb[i] = new ECaffinecord();
        EC_recva[i]->x = BN_new();
        EC_recva[i]->y = BN_new();
        EC_recvb[i]->x = BN_new();
        EC_recvb[i]->y = BN_new();
    }

    printf("  S_b sample omega_b  \n");
    printf("  S_b ----H_a=pi({A_}^{omega_b}), H_b=pi'(B'^{xi_b})----> S_a  \n");
    printf("  S_a compare H_a^{1/xi_a} with H_b  \n");
    printf("  S_a sample omega_a  \n");
    printf("  S_a ----K_a=pi(A'^{omega_a}), K_b=pi'(B_^{omega_a})----> S_b  \n");
    printf("  S_b compare K_a with K_b^{1/omega_b}  \n");

    BIGNUM *xi_inv_a = BN_new(), *xi_inv_b = BN_new();
    BN_mod_inverse(xi_inv_a, xi_a, ORDER, NULL);
    BN_mod_inverse(xi_inv_b, xi_b, ORDER, NULL);
    for (int j = 0; j < k; ++j){
        std::set<ECaffinecord*, ECPointComparator> EC_set;
        BIGNUM *omega_a = BN_new(), *omega_b = BN_new();
        if (party == ALICE) BN_rand(omega_a, 256, -1, 0);
        else BN_rand(omega_b, 256, -1, 0);

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
        if (party == ALICE) {
            ECmul_single(std::ref(group), Hb, Hb, std::ref(omega_a), N, thread_num);
        } else {
            ECmul_single(std::ref(group), Kb, Kb, std::ref(omega_b), N, thread_num);
        }
        std::vector<int> sigma, sigma_;
        if (party == ALICE) {
            sigma = random_permutation(seed_a, N+M);
            sigma_ = random_permutation(sigma[0], N+M);
            seed_a = sigma_[0];
        } else {
            sigma = random_permutation(seed_b, N+M);
            sigma_ = random_permutation(sigma[0], N+M);
            seed_b = sigma_[0];
        }
        seed_b = sigma_[0];
        for (int i = 0; i < N+M; ++i) {
            if (party == ALICE) {
                receive_EC_point(group, Ka[i], ios);
                receive_bn(EC_recvb[i]->x, ios);
                receive_bn(EC_recvb[i]->y, ios);
                send_EC_point(group, Ha[sigma[i]], ios);
                send_EC_point(group, Hb[sigma_[i]], ios);
            } else {
                send_EC_point(group, Ka[sigma[i]], ios);
                send_EC_point(group, Kb[sigma_[i]], ios);
                receive_EC_point(group, Ha[i], ios);
                receive_bn(EC_recvb[i]->x, ios);
                receive_bn(EC_recvb[i]->y, ios);
            }
        }
        if (party == ALICE) {
            ECmul_single(std::ref(group), Ka, Ka, std::ref(xi_inv_a), N+M, thread_num);
            for (int i = 0; i < N+M; ++i) {
                EC_set.insert(EC_recvb[i]);
                EC_POINT_get_affine_coordinates(group, Ka[i], EC_recva[i]->x, EC_recva[i]->y, ctx);
            }
        } else {
            ECmul_single(std::ref(group), Ha, Ha, std::ref(xi_inv_b), N+M, thread_num);
            for (int i = 0; i < N+M; ++i) {
                EC_set.insert(EC_recvb[i]);
                EC_POINT_get_affine_coordinates(group, Ha[i], EC_recva[i]->x, EC_recva[i]->y, ctx);
            }
        }
        clock_t cmp = clock();
        if (party == ALICE) {
            for (int i = 0; i < N+M; ++i) {
                if (EC_set.find(EC_recva[i]) != EC_set.end()) {
                    // printf("alice:%d\n", i);
                    sa->send_data(&i, sizeof(i));
                    sa->flush();
                }
            }
        } else {
            for (int i = 0; i < N+M; ++i) {
                // printf("bob:%d\n", i);
                if (EC_set.find(EC_recva[i]) != EC_set.end()) {
                    // printf("hit:%d\n", i);
                    sb->send_data(&i, sizeof(i));
                    sb->flush();
                }
            }
        }
        clock_t end_cmp = clock();
        double cmp_time = ((double)(end_cmp - cmp)) / CLOCKS_PER_SEC;
        printf("CMP runtime: %.6f seconds\n", cmp_time);
        BN_free(omega_a);
        BN_free(omega_b);
    }

    clock_t end = clock();
    double elapsed_time = ((double)(end - mid_)) / CLOCKS_PER_SEC;
    printf("Completed with N=%d.\n", N);
    printf("Mask time: %.6f seconds\n", elapsed_time); // 20N+18M ~55s

    clock_gettime(CLOCK_MONOTONIC, &finish);

    elapsed = (finish.tv_sec - startt.tv_sec);
    elapsed += (finish.tv_nsec - startt.tv_nsec) / 1000000000.0;
    printf("Total time: %.6f seconds\n", elapsed); 

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
