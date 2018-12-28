#include <string.h>
#include "merkle.h"

/* Merkle Tree
    The merkle tree is an array of levels,
    each level is an array of hashes
*/

#define MERKLE_INIT_LEVELS 16
#define MERKLE_INIT_HASHES 16

merkle_err_t merkle_init(merkle_t *m) {
    merkle_err_t err;

    err = array_init(&m->levels, MERKLE_INIT_LEVELS, sizeof(array_t));
    if (err != MERKLE_OK) {
        return err;
    }

    return MERKLE_OK;
}

void merkle_deinit(merkle_t *m) {
    for (uint32_t i = 0; i < array_len(&m->levels); i++) {
        array_t *level = array_get(&m->levels, i);
        array_deinit(level);
    }

    array_deinit(&m->levels);
}

merkle_hash_t *merkle_root(merkle_t *m) {
    return array_get(array_get(&m->levels, array_len(&m->levels) - 1), 0);
}

merkle_err_t merkle_add(merkle_t *m, merkle_hash_t hash) {
    merkle_hash_t hashcpy;
    merkle_err_t err;
    size_t level_idx = 0;
    int replace = 0;

    memcpy(hashcpy, hash, sizeof(hashcpy));

    do {
        array_t *level;
        merkle_hash_t *node;

        if (array_len(&m->levels) == level_idx) {
            level = array_push(&m->levels);
            if (level == NULL) {
                return MERKLE_ERROR;
            }

            err = array_init(level, MERKLE_INIT_HASHES, sizeof(*node));
            if (err != MERKLE_OK) {
                return err;
            }
        } else {
            level = array_get(&m->levels, level_idx);
        }

        node = replace && array_len(level) > 0 ? array_top(level) : array_push(level);
        if (node == NULL) {
            return MERKLE_ERROR;
        }

        memcpy(node, hashcpy, sizeof(*node));

        /* root level? */
        if (array_len(level) == 1) {
            break;
        }

        if (array_len(level) % 2 == 0) {
            /* we treat array_get(level, array_len(level)-2) as double width
                given that all siblings reside next to each other in a
                contiguous array */
            hash_md5(array_get(level, array_len(level)-2), hashcpy);
        }

        /* If we have an even number of hashes, replace top/last hash
        of next level. If we have an odd number we simply push the hash onto
        the next level. */
        replace = replace || array_len(level) % 2 == 0;

        level_idx++;
    } while(1);

    return MERKLE_OK;
}

#define MERKLE_PROOF_INIT_HASHES 4

merkle_err_t merkle_proof_init(merkle_proof_t *p) {
    merkle_err_t err;

    err = array_init(&p->hashes, MERKLE_PROOF_INIT_HASHES, sizeof(merkle_hash_t));
    if (err != MERKLE_OK) {
        return err;
    }
    err = array_init(&p->pos, MERKLE_PROOF_INIT_HASHES, sizeof(int));
    if (err != MERKLE_OK) {
        return err;
    }

    return MERKLE_OK;
}

void merkle_proof_deinit(merkle_proof_t *p) {
    array_deinit(&p->hashes);
    array_deinit(&p->pos);
}

merkle_err_t merkle_proof(merkle_proof_t *p, merkle_t *m, merkle_hash_t hash) {
    int i;
    int level_idx = 0;
    merkle_hash_t *node;
    merkle_hash_t *p_hash;
    int *pos;

    if (array_len(&m->levels) < 2) {
        return MERKLE_ERROR;
    }

    array_t *level = array_get(&m->levels, 0);
    for (i = 0; i < array_len(level); i++) {
        if(memcmp(hash, array_get(level, i), HASH_WIDTH) == 0) {
            break;
        }
    }

    if (i >= array_len(level)) {
        return MERKLE_NOTFOUND;
    }

    do {
        /* if i is even, sibling is on right
           if odd, sibling is on left */
        if(i % 2 == 0) {
            if (i == array_len(level) - 1) {
                /* this is the last leaf in a row with odd nodes (even idx),
                    we need to go up a level to find the "actual" leaf ...
                    see note in merkle_t about implementation ...
                    basically move up a level until we're at an odd index  */
                goto uplevel;
            }

            node = array_get(level, i+1);
        } else {
            node = array_get(level, i-1);
        }

        if (node == NULL) {
            return MERKLE_ERROR;
        }

        p_hash = array_push(&p->hashes);
        if (p_hash == NULL) {
            return MERKLE_ERROR;
        }
        memcpy(p_hash, node, sizeof(*p_hash));

        pos = array_push(&p->pos);
        if (pos == NULL) {
            return MERKLE_ERROR;
        }
        *pos = i % 2 == 0;

uplevel:
        /* parent is floor(i/2) */
        i = i / 2;
        level_idx++;
        level = array_get(&m->levels, level_idx);
    } while(array_len(level) != 1);

    return MERKLE_OK;
}

merkle_err_t merkle_proof_validate(merkle_proof_t *p, merkle_hash_t root, merkle_hash_t hash, int *valid) {
    merkle_hash_t result[2];
    int *pos, *lastpos;

    if (array_len(&p->hashes) < 1) {
        memcpy(result[0], hash, sizeof(*result));
    } else {
        pos = array_get(&p->pos, 0);
        memcpy(result[*pos ? 0 : 1], hash, sizeof(*result));
    }

    for (int i = 0; i < array_len(&p->hashes); i++) {
        pos = array_get(&p->pos, i);
        memcpy(result[*pos], array_get(&p->hashes, i), sizeof(*result));

        if (i < array_len(&p->hashes) - 1){
            pos = array_get(&p->pos, i+1);
            hash_md5(result[0], result[*pos ? 0 : 1]);
        } else {
            hash_md5(result[0], result[0]);
        }
    }

    *valid = memcmp(result[0], root, HASH_WIDTH) == 0;
    return MERKLE_OK;
}

/* Printing */

#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>

void merkle_print_hash(merkle_hash_t hash, int print_width) {
    for (int i = 0; i < print_width; i++) {
       printf("%02x", hash[i]);
    }
}

void merkle_print(merkle_t *m, int print_width) {
    struct winsize w;
    int midpoint;

    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    midpoint =  w.ws_col/2;

    printf("%*s%s\n", midpoint, "",".");

    for(int i = array_len(&m->levels)-1; i >= 0; i--) {
        /* midpoint minus the max number of hashes in the level multiplied by
            half their width */
        int indent = midpoint - (print_width/2)*(1 << (array_len(&m->levels)-i));
        array_t *level = array_get(&m->levels, i);

        /* to account for the hash seperator, we need to reduce the indent
            by the number of seperators that will appear to the left of the
            midpoint, which is half the max number of hashes at the level */
        if (i != array_len(&m->levels)-1) {
            indent -= (1 << (array_len(&m->levels)-i-2)) - 1;
        }
        if (indent < 0) indent = 0;

        printf("%*s", indent, "");

        for(int j = 0; j < array_len(level); j++) {
            merkle_hash_t *hash = array_get(level, j);

            if (j != 0) printf("|");

            merkle_print_hash(*hash, print_width);
        }

        printf("\n");
    }
}

void merkle_proof_print(merkle_proof_t *p, int print_width) {
    printf("=[");
    for (int i = 0; i < array_len(&p->hashes); i++) {
        merkle_hash_t *hash = array_get(&p->hashes, i);

        merkle_print_hash(*hash, print_width);
        if (i != array_len(&p->hashes) - 1) {
            printf(",");
        }
    }
    printf("]\n");
}

