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

/* Merkle Tree */
typedef struct _merkle_t merkle_t;
merkle_err_t merkle_init(merkle_t *m);
void merkle_deinit(merkle_t *m);
merkle_hash_t *merkle_root(merkle_t *m);
merkle_err_t merkle_add(merkle_t *m, merkle_hash_t hash);

/* WIP proof and audit */
merkle_hash_t *merkle_proof(merkle_t *m, uint32_t leaf_idx);

#endif /* MERKLE_H */