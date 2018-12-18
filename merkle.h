#ifndef MERKLE_H
#define MERKLE_H

/* This Merkle tree is effectively an array of hashes where the first n_leaves
    elements are hashes of the data being verified (e.g. txs in btc land) and
    the next ceil(n_leaves/2) nodes represent the next level k of the tree,
    the next ceil((n_leaves/2)/2) nodes represent the k+1 level, and so on;
    that is, the number of nodes in level k is ceil(n_leaves/2^k). The ith node
    of any level k where k!=0 is the hash of nodes_(k-1)[i*2]||nodes_(k-1)[i*2+1]
    if len(nodes_(k-1)) is even and nodes_(k-1)[i*2] if it's odd. */

typedef struct merkle_t {
    uint64_t n_leaves;
    merkle_node_t **nodes;
} merkle_t;

#endif /* MERKLE_H */