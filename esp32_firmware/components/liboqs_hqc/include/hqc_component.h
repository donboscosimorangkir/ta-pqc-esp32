#pragma once

#include <stdint.h>
#include <stddef.h>

typedef struct {
    void *kem;
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
} hqc_ctx_t;

/*
 * level:
 *   1 -> HQC-1
 *   3 -> HQC-3
 *   5 -> HQC-5
 */
int hqc_init(hqc_ctx_t *ctx, int level);

int hqc_cleanup(hqc_ctx_t *ctx);
int hqc_keypair(hqc_ctx_t *ctx);
int hqc_encaps(hqc_ctx_t *ctx, const uint8_t *public_key);
int hqc_decaps(hqc_ctx_t *ctx, const uint8_t *ciphertext);

size_t hqc_get_public_key_len(hqc_ctx_t *ctx);
size_t hqc_get_secret_key_len(hqc_ctx_t *ctx);
size_t hqc_get_ciphertext_len(hqc_ctx_t *ctx);
size_t hqc_get_shared_secret_len(hqc_ctx_t *ctx);
