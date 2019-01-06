#include <stdio.h>
#include <string.h>
#include "merkle.h"

#define PRINT_WIDTH 2
void test_hash(merkle_hash_t hash, hash_e c, uint32_t width) {
    merkle_t m;
    merkle_init(&m, c);
    for (int i = 0; i < strlen((const char *)hash); i += width) {
        merkle_add(&m, &hash[i]);
        merkle_print(&m, PRINT_WIDTH);

        for (int j = 0; j <= i; j+=width) {
            int valid;
            merkle_proof_t p;
            merkle_proof_init(&p, c);
            merkle_proof(&p, &m, &hash[j]);
            printf("Proof for ");
            merkle_print_hash(&hash[j], PRINT_WIDTH);
            merkle_proof_validate(&p, merkle_root(&m), &hash[j], &valid);
            printf(valid ? " (VALID) " : " (INVALID) ");
            printf("=");
            merkle_proof_print(&p, PRINT_WIDTH);
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

    #define TEST_HASH(_name, _width) test_hash(hash, HASH_##_name, _width);
    HASH_CODEC( TEST_HASH )
    #undef TEST_HASH
}