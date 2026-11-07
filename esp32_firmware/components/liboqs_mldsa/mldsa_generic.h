#pragma once

#include <stdint.h>
#include <stddef.h>

typedef struct {
    void *sig;               /* OQS_SIG* internal */
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *signature;
    size_t signature_len;    /* panjang aktual signature setelah sign() */
} mldsa_ctx_t;

/* level: 44, 65, atau 87 */
int mldsa_init(mldsa_ctx_t *ctx, int level);
int mldsa_cleanup(mldsa_ctx_t *ctx);
int mldsa_keypair(mldsa_ctx_t *ctx);
int mldsa_sign(mldsa_ctx_t *ctx, const uint8_t *message, size_t message_len);
int mldsa_verify(mldsa_ctx_t *ctx, const uint8_t *message, size_t message_len, const uint8_t *public_key);

size_t mldsa_get_public_key_len(mldsa_ctx_t *ctx);
size_t mldsa_get_secret_key_len(mldsa_ctx_t *ctx);
size_t mldsa_get_max_signature_len(mldsa_ctx_t *ctx);
