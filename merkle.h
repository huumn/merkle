#ifndef MERKLE_H
#define MERKLE_H

#include <stdlib.h>
#include <string.h>

/* Errors */
typedef enum merkle_err_t {
    MERKLE_OK,
    MERKLE_ERROR,
    MERKLE_ENOMEM,
    MERKLE_NOTFOUND,
} merkle_err_t;

/* Hashing
    TODO:
    1. set hash function/type on merkle init which will
    determine both the hashing function and width of the hashes
    2. wrappers around all openssl impls once we're linked
    3. make it clearer that input is actually double width hash_t
*/
#define HASH_WIDTH 16
typedef uint8_t merkle_hash_t[HASH_WIDTH];
void hash_md5(merkle_hash_t input, merkle_hash_t output);

/* TODO: I'd prefer these impls to be hidden ... even if they
don't need to be */
/* Arrays */
typedef struct array_t {
    uint32_t len;
    uint32_t cap;

    size_t item_size;
    void *items;
} array_t;

/* Merkle Tree */
typedef struct merkle_t {
    /* the bottom of the tree is levels[0], and the
    parents of levels[0] are on levels[1] and so on ...
    this implementation is kind of unusual in that all the
    leaves are in levels[0] and if any node doesn't have a sibling
    they are the parent of themselves */
    array_t levels;
} merkle_t;
merkle_err_t merkle_init(merkle_t *m);
void merkle_deinit(merkle_t *m);
merkle_hash_t *merkle_root(merkle_t *m);
merkle_err_t merkle_add(merkle_t *m, merkle_hash_t hash);
void merkle_print(merkle_t *m, int print_width);

/* WIP proof and audit? Is this how this should work? */
merkle_hash_t *merkle_proof(merkle_t *m, uint32_t leaf_idx);

#endif /* MERKLE_H */