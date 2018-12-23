#include <stdio.h>
#include "merkle.h"

int main() {
    printf("Testing Merkle Tree...\n");

    merkle_hash_t hash[] =  { { 0x61, 0x4e, 0xef, 0x5f, 0x3e, 0xc0, 0x73, 0xb9,
                                0xcc, 0x4c, 0x09, 0xd2, 0x11, 0xe2, 0x75, 0xaa, },
                              { 0xb7, 0x91, 0x3a, 0xa1, 0x5c, 0x43, 0xbe, 0x7d,
                                0x53, 0x4b, 0x4e, 0xec, 0x6e, 0x99, 0xe8, 0xa0, },
                              { 0x29, 0xbf, 0xe3, 0x72, 0x86, 0x57, 0x37, 0xfe,
                                0x2b, 0xfc, 0xfd, 0x36, 0x18, 0xb1, 0xda, 0x7d, },
                              { 0x7a, 0x67, 0x58, 0x83, 0xb1, 0xc1, 0x17, 0xe2,
                                0x67, 0x47, 0x0d, 0xce, 0x52, 0xeb, 0xa5, 0x18, },
                              { 0x12, 0x47, 0x0f, 0xe4, 0x06, 0xd4, 0x40, 0x17,
                                0xd9, 0x6e, 0xab, 0x37, 0xdd, 0x65, 0xfc, 0x14, },
                              { 0xd5, 0x12, 0xef, 0x9a, 0xf0, 0x61, 0x69, 0x86,
                                0x1d, 0x2e, 0x4d, 0x8d, 0xa2, 0xe4, 0x9e, 0x72, },
                              { 0x61, 0xcc, 0xef, 0x5f, 0x3e, 0xc0, 0x73, 0xb9,
                                0x7a, 0x4c, 0x09, 0xd2, 0x11, 0xe2, 0x75, 0xaa, },
                              { 0xb7, 0xcc, 0x3a, 0xa1, 0x5c, 0x43, 0xbe, 0x7d,
                                0xcc, 0x4b, 0x4e, 0xec, 0x6e, 0x99, 0xe8, 0xa0, },
                              { 0x29, 0xcc, 0xe3, 0x72, 0x86, 0x57, 0x37, 0xfe,
                                0xcc, 0xfc, 0xfd, 0x36, 0x18, 0xb1, 0xda, 0x7d, },
                              { 0x7a, 0xcc, 0x58, 0x83, 0xb1, 0xc1, 0x17, 0xe2,
                                0xcc, 0x47, 0x0d, 0xce, 0x52, 0xeb, 0xa5, 0x18, },
                              { 0x61, 0x4e, 0xb1, 0x5f, 0x3e, 0xc0, 0x73, 0xb9,
                                0x7a, 0x4c, 0x09, 0xd2, 0x11, 0xe2, 0x75, 0xaa, },
                              { 0xb7, 0x91, 0xef, 0xa1, 0x5c, 0x43, 0xbe, 0x7d,
                                0xcc, 0x4b, 0x4e, 0xec, 0x6e, 0x99, 0xe8, 0xa0, },
                              { 0x29, 0xbf, 0xef, 0x72, 0x86, 0x57, 0x37, 0xfe,
                                0xcc, 0xfc, 0xfd, 0x36, 0x18, 0xb1, 0xda, 0x7d, },
                              { 0x7a, 0x67, 0xef, 0x83, 0xb1, 0xc1, 0x17, 0xe2,
                                0xcc, 0x47, 0x0d, 0xce, 0x52, 0xeb, 0xa5, 0x18, },
                              { 0xd9, 0xbc, 0xef, 0x74, 0x86, 0x57, 0x37, 0xfe,
                                0xcc, 0xfc, 0xfd, 0x36, 0x18, 0xb1, 0xda, 0x7d, },
                              { 0xda, 0x6c, 0xef, 0x8f, 0xb1, 0xc1, 0x17, 0xe2,
                                0xcc, 0x47, 0x0d, 0xce, 0x52, 0xeb, 0xa5, 0x18, },
                            };

    merkle_t m;
    merkle_init(&m);
    for (int i = 0; i < sizeof(hash) / sizeof(hash[1]); i++) {
        merkle_add(&m, hash[i]);
        merkle_print(&m, 4);

        for (int j = 0; j <= i; j++) {
            int valid;
            merkle_proof_t p;
            merkle_proof_init(&p);
            merkle_proof(&p, &m, hash[j]);
            printf("Proof for ");
            merkle_print_hash(hash[j], 4);
            merkle_proof_validate(&p, *merkle_root(&m), hash[j], &valid);
            printf(valid ? " (VALID) " : " (INVALID) ");
            printf("=");
            merkle_proof_print(&p, 4);
            merkle_proof_deinit(&p);
        }
    }
    merkle_deinit(&m);
}