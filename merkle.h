#ifndef MERKLE_H
#define MERKLE_H

/* Errors */

typedef enum merkle_err_t {
    MERKLE_OK,
    MERKLE_ERROR,
    MERKLE_ENOMEM,
    MERKLE_NOTFOUND,
} merkle_err_t;

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

void *array_pop(array_t *a) {
    return array_get(a, a->len-1);
}

/* Merkle Tree
    The merkle tree is an array of levels,
    each level is an array of hashes
*/

#define MERKLE_INIT_LEVELS 16
#define MERKLE_INIT_HASHES 16
#define HASH_WIDTH 32
typedef uint8_t merkle_hash_t[HASH_WIDTH];

typedef struct merkle_t {
    /* leaves are on levels[0], if levels[0].len > 1,
    the leaves parents are on levels[1] and so on */
    array_t levels;
} merkle_t;

merkle_err_t merkle_init(merkle_t *m) {
    merkle_err_t err;

    err = array_init(&m->levels, MERKLE_INIT_LEVELS, sizeof(array_t))
    if (err != MERKLE_OK) {
        return err;
    }

    return MERKLE_OK;
}

void merkle_deinit(merkle_t *m) {
    for (uint32_t i = 0; i < m->levels.len; i++) {
        array_t *level = array_get(m->levels, i);
        array_deinit(level);
    }

    array_deinit(&m->levels);
}

merkle_hash_t *merkle_root(merkle_t *m) {
    return array_get(array_get(m->levels, m->levels.len - 1), 0);
}

merkle_err_t merkle_add(merkle_t *m, merkle_hash_t *hash) {
    size_t level_idx = 0;
    int replace = 0;

    do {
        array_t *level;
        merkle_hash_t *_hash;

        if (m->levels.len == level_idx) {
            level = array_push(&m->levels);
            if (level == NULL) {
                return MERKLE_ERROR;
            }

            err = array_init(&level, MERKLE_INIT_HASHES, sizeof(*_hash))
            if (err != MERKLE_OK) {
                return err;
            }
        } else {
            level = array_get(&m->levels, level_idx);
        }

        _hash = replace ? array_top(level) : array_push(level);
        if (_hash == NULL) {
            return MERKLE_ERROR;
        }

        memcpy(_hash, hash, sizeof(*hash));

        /* root level? */
        if (level->len == 1) {
            break;
        }

        /* If we have an even number of hashes, replace top hash
        of next level. If we have an odd we simply push on the hash. */
        replace = level->len % 2 == 0;
        if (replace) {
            hash = /* hash(hash||array_get(level, level->len-1)) */
        } else {
            hash = /* hash(hash) */
        }

        level_idx++;
    } while(1);

    return MERKLE_OK;
}

#endif /* MERKLE_H */