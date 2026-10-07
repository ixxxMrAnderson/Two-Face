#include "run_receive.cpp"
#include "run_reconstruct.cpp"

int main(int argc, char* argv[]) {
    OpenSSL_add_all_algorithms();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    if (argc < 2) {
        printf("usage: %s <Sa|Sb|C> [threads] [timeout_sec]\n", argv[0]);
        return 1;
    }
    party_name = argv[1];
    if (argc > 2) thread_num = atoi(argv[2]);
    if (thread_num < 1) thread_num = 1;
    if (argc > 3) net_timeout_sec = atoi(argv[3]);
    // A send to a dead peer must fail in net_send, not kill the process silently.
    signal(SIGPIPE, SIG_IGN);
    g_pool = new WorkerPool(thread_num);
    NetIO *ios_ss[1] = {nullptr}, *ios_sac = nullptr, *ios_sbc = nullptr;
    setup_netio(party_name, ios_ss, ios_sac, ios_sbc, 8000);
    

    BIGNUM *sk_a = BN_new(), *sk_b = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *ORDER = BN_new();
    EC_GROUP_get_order(group, ORDER, ctx);
    EC_POINT *pk = EC_POINT_new(group); 
    unsigned char seed[16] = {0};
    PRG *prg = new PRG(seed);
    if (party_name == "C") {
        EC_POINT *pka = EC_POINT_new(group), *pkb = EC_POINT_new(group);
        random_BN(prg, sk_a);
        random_BN(prg, sk_b);
        EC_POINT_mul(group, pka, sk_a, NULL, NULL, NULL);
        EC_POINT_mul(group, pkb, sk_b, NULL, NULL, NULL);
        EC_POINT_add(group, pk, pka, pkb, NULL);
        send_EC_point(group, pk, ios_sac);
        send_EC_point(group, pk, ios_sbc);
        EC_POINT_free(pka);
        EC_POINT_free(pkb);
    } else if (party_name == "Sa") {
        receive_EC_point(group, pk, ios_sac);
    } else {
        receive_EC_point(group, pk, ios_sbc);
    }

    EC_POINT **c1 = (EC_POINT **)malloc(N * sizeof(EC_POINT *));
    EC_POINT **c2 = (EC_POINT **)malloc(N * sizeof(EC_POINT *));

    Request *R;
    run_request(group, ios_sac, ios_sbc, party_name, R, sk_a, sk_b, ctx, prg);
    unsigned char buffer[32];
    prg->random_data(buffer, 32);    
    BIGNUM *r = BN_bin2bn(buffer, 32, nullptr);
    for (int i = 0; i < N; ++i) {
        prg->random_data(buffer, 32);    
        BIGNUM *r = BN_bin2bn(buffer, 32, nullptr);
        c1[i] = EC_POINT_new(group);
        EC_POINT_mul(group, c1[i], r, NULL, NULL, ctx);
        c2[i] = EC_POINT_new(group);
        if (i < P) EC_POINT_mul(group, c2[i], NULL, pk, r, ctx);
        else {
            prg->random_data(buffer, 32);    
            BIGNUM *r_ = BN_bin2bn(buffer, 32, nullptr);
            EC_POINT_mul(group, c2[i], r_, NULL, NULL, ctx);
            BN_free(r_);
        }
        BN_free(r);
    }
    
    if (party_name == "Sa" or party_name == "Sb") {
        run_receive(group, ios_ss, ios_sac, ios_sbc, party_name, c1, c2, R);
    } else {
        size_t key_size = ios_sac->counter+ios_sbc->counter;
        run_reconstruct(ios_sac, ios_sbc, R->seed_a, R->seed_b);
    }
}

// 369.470033+28.304488+13.831352+9.713220
// 161.832885+12.569952+5.759053+1.772165
// 186.098604+15.496010+7.382856+3.9
// 216.261165+19.160552+9.412050+3.024313
// 244.764750+22.562164+10.952460+3.833765