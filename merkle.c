#include <string.h>
#include "merkle.h"

/* Merkle Tree
    The merkle tree is an array of levels,
    each level is an array of hashes
*/

#define MERKLE_INIT_LEVELS 16
#define MERKLE_INIT_HASHES 16

uint32_t get_hash_width(hash_e c) {
    #define HASH_WIDTHS(_name, _width) _width,
    uint32_t hash_widths[] = {
        HASH_CODEC( HASH_WIDTHS )
    };
    #undef HASH_WIDTHS

    return hash_widths[c];
}

static hash_func get_hash_func(hash_e c) {
    #define HASH_FUNCS(_name, _width) &hash_##_name,
    hash_func hash_funcs[] = {
        HASH_CODEC( HASH_FUNCS )
    };
    #undef HASH_FUNCS

    return hash_funcs[c];
}

merkle_err_t merkle_init(merkle_t *m, hash_e c) {
    merkle_err_t err;

    err = array_init(&m->levels, MERKLE_INIT_LEVELS, sizeof(array_t));
    if (err != MERKLE_OK) {
        return err;
    }

    m->hash_width = get_hash_width(c);
    m->hash_func = get_hash_func(c);

    return MERKLE_OK;
}

void merkle_deinit(merkle_t *m) {
    for (uint32_t i = 0; i < array_len(&m->levels); i++) {
        array_t *level = array_get(&m->levels, i);
        array_deinit(level);
    }

    array_deinit(&m->levels);
}

merkle_hash_t merkle_root(merkle_t *m) {
    return array_get(array_get(&m->levels, array_len(&m->levels) - 1), 0);
}

merkle_err_t merkle_add(merkle_t *m, merkle_hash_t hash) {
    merkle_err_t err;
    uint8_t hashcpy[m->hash_width];
    size_t level_idx = 0;
    int replace = 0;

    memcpy(hashcpy, hash, m->hash_width);

    do {
        array_t *level;
        merkle_hash_t *node;

        if (array_len(&m->levels) == level_idx) {
            level = array_push(&m->levels);
            if (level == NULL) {
                return MERKLE_ERROR;
            }

            err = array_init(level, MERKLE_INIT_HASHES, m->hash_width);
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

        memcpy(node, hashcpy, m->hash_width);

        /* root level? */
        if (array_len(level) == 1) {
            break;
        }

        if (array_len(level) % 2 == 0) {
            /* we treat array_get(level, array_len(level)-2) as double width
                given that all siblings reside next to each other in a
                contiguous array */
            m->hash_func(array_get(level, array_len(level)-2), hashcpy);
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

merkle_err_t merkle_proof_init(merkle_proof_t *p, hash_e c) {
    merkle_err_t err;

    err = array_init(&p->hashes, MERKLE_PROOF_INIT_HASHES, p->hash_width);
    if (err != MERKLE_OK) {
        return err;
    }

    err = array_init(&p->left_right, MERKLE_PROOF_INIT_HASHES, sizeof(int));
    if (err != MERKLE_OK) {
        return err;
    }

    p->hash_width = get_hash_width(c);
    p->hash_func = get_hash_func(c);

    return MERKLE_OK;
}

void merkle_proof_deinit(merkle_proof_t *p) {
    array_deinit(&p->hashes);
    array_deinit(&p->left_right);
}

merkle_err_t merkle_proof(merkle_proof_t *p, merkle_t *m, merkle_hash_t hash) {
    int i;
    int level_idx = 0;
    merkle_hash_t node;
    merkle_hash_t p_hash;
    int *pos;

    if (array_len(&m->levels) < 2) {
        return MERKLE_ERROR;
    }

    array_t *level = array_get(&m->levels, 0);
    for (i = 0; i < array_len(level); i++) {
        if(memcmp(hash, array_get(level, i), p->hash_width) == 0) {
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
        memcpy(p_hash, node, p->hash_width);

        pos = array_push(&p->left_right);
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

/* TODO: cleanup */
merkle_err_t merkle_proof_validate(merkle_proof_t *p, merkle_hash_t root,
    merkle_hash_t hash, int *valid) {
    int *pos;
    int *lastpos;
    int left_right;
    uint8_t result[p->hash_width*2];

    if (array_len(&p->hashes) < 1) {
        left_right = 0;
    } else {
        pos = array_get(&p->left_right, 0);
        left_right = *pos ? 0 : 1;
    }
    memcpy(result+(left_right*p->hash_width), hash, p->hash_width);


    for (int i = 0; i < array_len(&p->hashes); i++) {
        pos = array_get(&p->left_right, i);
        memcpy(result+((*pos)*p->hash_width), array_get(&p->hashes, i), p->hash_width);

        left_right = 0;
        if (i < array_len(&p->hashes) - 1){
            pos = array_get(&p->left_right, i+1);
            left_right = *pos ? 0 : 1;
        }

        p->hash_func(result, result+(left_right*p->hash_width));
    }

    *valid = memcmp(result, root, p->hash_width) == 0;
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
            merkle_hash_t hash = array_get(level, j);

            if (j != 0) printf("|");

            merkle_print_hash(hash, print_width);
        }

        printf("\n");
    }
}

void merkle_proof_print(merkle_proof_t *p, int print_width) {
    printf("=[");
    for (int i = 0; i < array_len(&p->hashes); i++) {
        merkle_hash_t hash = array_get(&p->hashes, i);

        merkle_print_hash(hash, print_width);
        if (i != array_len(&p->hashes) - 1) {
            printf(",");
        }
    }
    printf("]\n");
}

