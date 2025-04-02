#include "util.h"

void run_reconstruct(NetIO *sa, NetIO *sb, int seed_a, int seed_b) {
    std::set<int> Pm;
    std::vector<int> sigma;
    clock_t start = clock();
    int tmp;
    for (int j = 0; j < k; ++j){
        std::vector<int> sigma = random_permutation(seed_b, N+M);
        for (int i = 0; i < P+M; ++i) {
            sa->recv_data(&tmp, sizeof(tmp));
            // printf("%d ",tmp);
            if (j == 0) Pm.insert(sigma[tmp]);
            else if (Pm.find(sigma[tmp]) == Pm.end()) {
                printf("Client Abort.\n");
                // return;
            }
        }
        // printf("\n");
        sigma = random_permutation(sigma[0], N+M);
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
            sb->recv_data(&tmp, sizeof(tmp));
            // printf("%d ",tmp);
            if (Pm.find(sigma[tmp]) == Pm.end()) {
                printf("Client Abort.\n");
                return;
            }
        }
        // printf("\n");
        sigma = random_permutation(sigma[0], N+M);
        seed_a = sigma[0];
    }

    clock_t end = clock();
    double construct_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Reconstruction time: %.6f seconds\n", construct_time);
}