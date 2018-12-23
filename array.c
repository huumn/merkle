#include "merkle.h"

merkle_err_t array_init(array_t *a, uint32_t cap, size_t item_size) {
    a->items = calloc(cap,  item_size);
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