#ifndef MERKLE_MERKLE_H
#define MERKLE_MERKLE_H

#include <stdlib.h>

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

merkle_err_t array_init(array_t *a, uint32_t cap, size_t item_size);
void array_deinit(array_t *a);
void *array_push(array_t *a);
void *array_get(array_t *a, uint32_t idx);
void *array_top(array_t *a);
static inline uint32_t array_len(array_t *a) {
    return a->len;
}

/* Hashing
*/
typedef uint8_t *merkle_hash_t;
typedef void (*hash_func)(merkle_hash_t, merkle_hash_t);

/* To add a new hash, add an ACTION(<hash name>, <width>) below.
    This (1) declares a function
        'void hash_<hash name>(merkle_hash_t in, merkle_hash_t out)'
        where 'in' is a double width merkle_hash_t (2*<width>) and out
        is just <width>
    (2) defines an enum in hash_e
        'HASH_<hash name>'
*/
#define HASH_CODEC(ACTION)   \
    ACTION( MD5, 16 )        \
    ACTION( SHA256, 32 )     \

#define HASH_ENUM(_name, _width) HASH_##_name,
typedef enum hash_e {
    HASH_CODEC(HASH_ENUM)
} hash_e;
#undef HASH_ENUM

#define HASH_FUNC(_name, _width) void hash_##_name(merkle_hash_t, merkle_hash_t);
HASH_CODEC(HASH_FUNC)
#undef HASH_FUNC

/* Merkle Tree */
typedef struct merkle_t {
    /* the bottom of the tree is levels[0], and the
    parents of levels[0] are on levels[1] and so on ...
    this implementation is kind of unusual in that all the
    leaves are in levels[0] and if any node doesn't have a sibling
    they are the parent of themselves */
    array_t levels;

    hash_func hash_func;
    uint32_t hash_width;
} merkle_t;
merkle_err_t merkle_init(merkle_t *m, hash_e c);
void merkle_deinit(merkle_t *m);
merkle_hash_t merkle_root(merkle_t *m);
merkle_err_t merkle_add(merkle_t *m, merkle_hash_t hash);
void merkle_print(merkle_t *m, int print_width);
void merkle_print_hash(merkle_hash_t hash, int print_width);

/* Merkle Proof */
typedef struct merkle_proof_t {
    /* A proof is just list of hashes where
    the hash to be validated can be hashed with hashes[0]
    and that result is hashed with hashes[1], and that result
    with hashes[2] and so on ... such that the resulting hash
    is the root hash of its merkle tree ... left_right tells
    us the concantenation order as we move to the root */
    array_t left_right;
    array_t hashes;

    hash_func hash_func;
    uint32_t hash_width;
} merkle_proof_t;
merkle_err_t merkle_proof_init(merkle_proof_t *p, hash_e c);
void merkle_proof_deinit(merkle_proof_t *p);
merkle_err_t merkle_proof(merkle_proof_t *p, merkle_t *m, merkle_hash_t hash);
merkle_err_t merkle_proof_validate(merkle_proof_t *p, merkle_hash_t root,
    merkle_hash_t hash, int *valid);
void merkle_proof_print(merkle_proof_t *p, int print_width);

#endif /* MERKLE_MERKLE_H */