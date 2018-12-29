#include <stdio.h>
#include <string.h>
#include "merkle.h"

void test_cipher(merkle_hash_t hash, cipher_e c, uint32_t width) {
    merkle_t m;
    merkle_init(&m, c);
    for (int i = 0; i < 32*8; i += width) {
        merkle_add(&m, &hash[i]);
        merkle_print(&m, 2);

        for (int j = 0; j <= i; j+=width) {
            int valid;
            merkle_proof_t p;
            merkle_proof_init(&p, c);
            merkle_proof(&p, &m, &hash[j]);
            printf("Proof for ");
            merkle_print_hash(&hash[j], 2);
            merkle_proof_validate(&p, merkle_root(&m), &hash[j], &valid);
            printf(valid ? " (VALID) " : " (INVALID) ");
            printf("=");
            merkle_proof_print(&p, 2);
            merkle_proof_deinit(&p);
        }
    }
    merkle_deinit(&m);
}

int main() {
    printf("Testing Merkle Tree...\n");

    merkle_hash_t hash = (merkle_hash_t)
                         "fdajfeoiafoiejiojfejaoijfeoancxz"
                         "823832ry7q9fgyipblvbsagf9qfhe9wq"
                         "yrhq97h324bfriy34gbsvhlbsvbdksjn"
                         "fush89q34u082yr8wnvskjv;nds3ewee"
                         "asfo38824h4343484t3hyehwugrhunmm"
                         "2323jju2u3249837gasbvcvau42yyqwq"
                         ";];[]p-=3424r3rjwqijifjvhsvhsduu"
                         "!@#$WGREWGR$%#%% #$%$agrewgewgew";

    #define TEST_CIPHER(_name, _width) test_cipher(hash, CIPHER_##_name, _width);
    CIPHER_CODEC( TEST_CIPHER )
    #undef TEST_CIPHER
}