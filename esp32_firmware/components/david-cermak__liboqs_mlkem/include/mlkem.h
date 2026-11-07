#ifndef MLKEM_H
#define MLKEM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *kem;
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
    int level;
} mlkem_ctx_t;

/*
 * level:
 *   512  -> ML-KEM-512
 *   768  -> ML-KEM-768
 *   1024 -> ML-KEM-1024
 */
int mlkem_init(mlkem_ctx_t *ctx, int level);

int mlkem_keypair(mlkem_ctx_t *ctx);
int mlkem_encaps(mlkem_ctx_t *ctx, const uint8_t *public_key);
int mlkem_decaps(mlkem_ctx_t *ctx, const uint8_t *ciphertext);
int mlkem_cleanup(mlkem_ctx_t *ctx);

const char *mlkem_get_algorithm_name(mlkem_ctx_t *ctx);
size_t mlkem_get_public_key_len(mlkem_ctx_t *ctx);
size_t mlkem_get_secret_key_len(mlkem_ctx_t *ctx);
size_t mlkem_get_ciphertext_len(mlkem_ctx_t *ctx);
size_t mlkem_get_shared_secret_len(mlkem_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
