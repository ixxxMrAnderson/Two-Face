#include "run_receive.cpp"
#include "run_reconstruct.cpp"

std::string party_name;

int main(int argc, char* argv[]) {
    OpenSSL_add_all_algorithms();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    party_name = argv[1];
    NetIO *ios_ss, *ios_sac, *ios_sbc;
    if (party_name == "Sa") {
        ios_ss = new NetIO(nullptr, 39844);
        ios_sac = new NetIO("127.0.0.1", 39845);
    } else if (party_name == "Sb") {
        ios_ss = new NetIO("127.0.0.1", 39844);
        ios_sbc = new NetIO(nullptr, 39846);
    } else if (party_name == "C") {
        ios_sac = new NetIO(nullptr, 39845);
        ios_sbc = new NetIO("127.0.0.1", 39846);
    }
    

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
        printf("Server2server communication: %llu KB\n", ios_ss->counter/1024);
    } else {
        size_t key_size = ios_sac->counter+ios_sbc->counter;
        printf("Request key size: %llu bytes\n", key_size);
        run_reconstruct(ios_sac, ios_sbc, R->seed_a, R->seed_b);
        printf("Digest size: %llu bytes\n", ios_sac->counter+ios_sbc->counter-key_size);
    }
}

// Detector total runtime: 400 s
// Recipient reconstruction time: 0.16s
// Receipt -> Sender: 65 Bytes
// Receipt -> Server(s): 1064 Bytes
// Server <-> Server: 220 MB
// Digest size: 