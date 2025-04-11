#include "util.h"

void run_reconstruct(NetIO *sa, NetIO *sb, int seed_a, int seed_b) {
    std::set<int> Pm;
    std::vector<int> recva;
    std::vector<int> recvb;
    std::vector<int> sigma;
    int tmp;
    for (int j = 0; j < k; ++j){
        for (int i = 0; i < P+M; ++i) {
            sa->recv_data(&tmp, sizeof(tmp));
            recva.push_back(tmp);
            // printf("recva: %d\n", recva.back());
            sb->recv_data(&tmp, sizeof(tmp));
            recvb.push_back(tmp);
            // printf("recvb: %d\n", recvb.back());
        }
    }
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int j = 0; j < k; ++j){
        std::vector<int> sigma = random_permutation(seed_b, N+M);
        // printf("sigma: ");
        // for (int i = 0; i < N+M; ++i) printf("%d ", sigma[i]);
        // printf("\n");
        for (int i = 0; i < P+M; ++i) {
            if (j == 0) {
                // printf("i=%d, j=%d, %d, %d\n", i, j, recva[j*k+i], sigma[recva[j*k+i]]);
                Pm.insert(sigma[recva[j*(P+M)+i]]);
            }
            else if (Pm.find(sigma[recva[j*(P+M)+i]]) == Pm.end()) {
                // printf("i=%d, j=%d, %d, %d\n", i, j, recva[j*k+i], sigma[recva[j*k+i]]);
                printf("Client Abort.\n");
                // return;
            }
        }
        seed_b = sigma[0];
        if (j == 0) {
            for (int i = 0; i < M; ++i) {
                if (Pm.find(N+i) == Pm.end()) {
                    printf("Client Abort.\n");
                    // return;
                }
            }
        }
        sigma = random_permutation(seed_a, N+M);
        for (int i = 0; i < P+M; ++i) {
            // printf("%d ",tmp);
            if (Pm.find(sigma[recvb[j*(P+M)+i]]) == Pm.end()) {
                // printf("i=%d, j=%d, %d, %d\n", i, j, recvb[j*k+i], sigma[recvb[j*k+i]]);
                printf("Client Abort.\n");
                return;
            }
        }
        seed_a = sigma[0];
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec);
    elapsed += (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("Reconstruction time: %.6f seconds\n", elapsed); 
}