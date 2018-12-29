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
    TODO:
    1. set hash function/type on merkle init which will
    determine both the hashing function and width of the hashes
    2. wrappers around all openssl impls once we're linked
    3. make it clearer that input is actually double width hash_t
*/
typedef uint8_t *merkle_hash_t;
typedef void (*cipher_func)(merkle_hash_t, merkle_hash_t);

/* To add a new cipher, add an ACTION(<cipher name>, <width>) below.
    This (1) declares a function
        'void hash_<cipher name>(merkle_hash_t in, merkle_hash_t out)'
        where 'in' is a double width merkle_hash_t (2*<width>) and out
        is just <width>
    (2) defines an enum in cipher_e
        'CIPHER_<cipher name>'
*/
#define CIPHER_CODEC(ACTION) \
    ACTION( MD5, 16 )        \

#define CIPHER_ENUM(_name, _width) CIPHER_##_name,
typedef enum cipher_e {
    CIPHER_CODEC(CIPHER_ENUM)
} cipher_e;
#undef CIPHER_ENUM

/* XXX Can we define this as cipher_func hash_##name? */
#define CIPHER_FUNC(_name, _width) void hash_##_name(merkle_hash_t, merkle_hash_t);
CIPHER_CODEC(CIPHER_FUNC)
#undef CIPHER_FUNC

/* Merkle Tree */
typedef struct merkle_t {
    /* the bottom of the tree is levels[0], and the
    parents of levels[0] are on levels[1] and so on ...
    this implementation is kind of unusual in that all the
    leaves are in levels[0] and if any node doesn't have a sibling
    they are the parent of themselves */
    array_t levels;

    /* XXX abstract these out into a struct ?*/
    cipher_func hash_func;
    uint32_t hash_width;
} merkle_t;
merkle_err_t merkle_init(merkle_t *m, cipher_e c);
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
    is the root hash of its merkle tree ... leaf_idx tells
    us the starting concantenation order as we move to the root */
    /* TODO: rename left_right */
    array_t pos;
    array_t hashes;

    cipher_func hash_func;
    uint32_t hash_width;
} merkle_proof_t;
merkle_err_t merkle_proof_init(merkle_proof_t *p, cipher_e c);
void merkle_proof_deinit(merkle_proof_t *p);
merkle_err_t merkle_proof(merkle_proof_t *p, merkle_t *m, merkle_hash_t hash);
merkle_err_t merkle_proof_validate(merkle_proof_t *p, merkle_hash_t root,
    merkle_hash_t hash, int *valid);
void merkle_proof_print(merkle_proof_t *p, int print_width);

#endif /* MERKLE_MERKLE_H */