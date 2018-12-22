#include "merkle.h"

/* Arrays */

typedef struct array_t {
    uint32_t len;
    uint32_t cap;

    size_t item_size;
    void *items;
} array_t;

merkle_err_t array_init(array_t *a, uint32_t cap, size_t item_size) {
    a->items = calloc(cap,  a->item_size);
    if (a->items == NULL) {
        return MERKLE_ENOMEM;
    }

    a->cap = cap;
    a->len = 0;
    a->item_size = item_size;

    return MERKLE_OK;
}

void array_deinit(array_t *a) {
    free(a->items);
}

void *array_push(array_t *a) {
    void *item;

    if (a->len == a->cap) {
        void *new_items;

        new_items = realloc(a->items, 2 * a->item_size * a->cap);
        if (new_items == NULL) {
            return NULL;
        }

        a->items = new_items;
        a->cap *= 2;
    }

    item = (uint8_t *)a->items + a->item_size * a->len;
    a->len++;

    return item;
}

void *array_get(array_t *a, uint32_t idx) {
    void *item;
    item = (uint8_t *)a->items + a->item_size * idx;
    return item;
}

void *array_top(array_t *a) {
    return array_get(a, a->len-1);
}

static inline uint32_t array_len(array_t *a) {
    return a->len;
}

/* Merkle Tree
    The merkle tree is an array of levels,
    each level is an array of hashes
*/

#define MERKLE_INIT_LEVELS 16
#define MERKLE_INIT_HASHES 16

struct _merkle_t {
    /* the bottom of the tree is levels[0], and the
    parents of levels[0] are on levels[1] and so on ...
    this implementation is kind of unusual in that all the
    leaves are in levels[0] and if any node doesn't have a sibling
    they are the parent of themselves */
    array_t levels;
};

merkle_err_t merkle_init(merkle_t *m) {
    merkle_err_t err;

    err = array_init(&m->levels, MERKLE_INIT_LEVELS, sizeof(array_t));
    if (err != MERKLE_OK) {
        return err;
    }

    return MERKLE_OK;
}

void merkle_deinit(merkle_t *m) {
    for (uint32_t i = 0; i < m->levels.len; i++) {
        array_t *level = array_get(&m->levels, i);
        array_deinit(level);
    }

    array_deinit(&m->levels);
}

merkle_hash_t *merkle_root(merkle_t *m) {
    return array_get(array_get(&m->levels, m->levels.len - 1), 0);
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

        if (m->levels.len == level_idx) {
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

        node = replace ? array_top(level) : array_push(level);
        if (node == NULL) {
            return MERKLE_ERROR;
        }

        memcpy(node, hashcpy, sizeof(*node));

        /* root level? */
        if (level->len == 1) {
            break;
        }

        /* If we have an even number of hashes, replace top hash
        of next level. If we have an odd we simply push on the hash onto
        the next level until it has a sibling */
        replace = level->len % 2 == 0;
        if (replace) {
            /* hash(array_get(level, level->len-2)||hash) is
                equivilant to treating array_get(level, level->len-2)
                as double width given that the siblings reside in
                a contiguous array */
            hash_md5(array_get(level, level->len-2), hashcpy);
        }

        level_idx++;
    } while(1);

    return MERKLE_OK;
}

