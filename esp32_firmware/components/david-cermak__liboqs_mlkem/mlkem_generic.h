#pragma once

#include <stdint.h>
#include <stddef.h>

typedef struct {
    void *kem;              /* OQS_KEM* internal */
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
} mlkem_ctx_t;

/* level: 512, 768, atau 1024 */
int mlkem_init(mlkem_ctx_t *ctx, int level);
int mlkem_cleanup(mlkem_ctx_t *ctx);
int mlkem_keypair(mlkem_ctx_t *ctx);
int mlkem_encaps(mlkem_ctx_t *ctx, const uint8_t *public_key);
int mlkem_decaps(mlkem_ctx_t *ctx, const uint8_t *ciphertext);

size_t mlkem_get_public_key_len(mlkem_ctx_t *ctx);
size_t mlkem_get_secret_key_len(mlkem_ctx_t *ctx);
size_t mlkem_get_ciphertext_len(mlkem_ctx_t *ctx);
size_t mlkem_get_shared_secret_len(mlkem_ctx_t *ctx);
