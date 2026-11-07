#include "mlkem_generic.h"
#include <oqs/oqs.h>
#include <oqs/kem.h>
#include <stdlib.h>

int mlkem_init(mlkem_ctx_t *ctx, int level)
{
    if (ctx == NULL) return -1;

    const char *alg;
    switch (level) {
        case 512:  alg = OQS_KEM_alg_ml_kem_512;  break;
        case 768:  alg = OQS_KEM_alg_ml_kem_768;  break;
        case 1024: alg = OQS_KEM_alg_ml_kem_1024; break;
        default: return -1;
    }

    OQS_init();

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (kem == NULL) return -1;
    ctx->kem = kem;

    ctx->public_key    = malloc(kem->length_public_key);
    ctx->secret_key    = malloc(kem->length_secret_key);
    ctx->ciphertext    = malloc(kem->length_ciphertext);
    ctx->shared_secret = malloc(kem->length_shared_secret);

    if (!ctx->public_key || !ctx->secret_key || !ctx->ciphertext || !ctx->shared_secret) {
        mlkem_cleanup(ctx);
        return -1;
    }
    return 0;
}

int mlkem_keypair(mlkem_ctx_t *ctx)
{
    if (ctx == NULL || ctx->kem == NULL) return -1;
    OQS_KEM *kem = (OQS_KEM *)ctx->kem;
    return (OQS_KEM_keypair(kem, ctx->public_key, ctx->secret_key) == OQS_SUCCESS) ? 0 : -1;
}

int mlkem_encaps(mlkem_ctx_t *ctx, const uint8_t *public_key)
{
    if (ctx == NULL || ctx->kem == NULL || public_key == NULL) return -1;
    OQS_KEM *kem = (OQS_KEM *)ctx->kem;
    return (OQS_KEM_encaps(kem, ctx->ciphertext, ctx->shared_secret, public_key) == OQS_SUCCESS) ? 0 : -1;
}

int mlkem_decaps(mlkem_ctx_t *ctx, const uint8_t *ciphertext)
{
    if (ctx == NULL || ctx->kem == NULL || ciphertext == NULL) return -1;
    OQS_KEM *kem = (OQS_KEM *)ctx->kem;
    return (OQS_KEM_decaps(kem, ctx->shared_secret, ciphertext, ctx->secret_key) == OQS_SUCCESS) ? 0 : -1;
}

int mlkem_cleanup(mlkem_ctx_t *ctx)
{
    if (ctx == NULL) return 0;
    if (ctx->public_key)    free(ctx->public_key);
    if (ctx->secret_key)    free(ctx->secret_key);
    if (ctx->ciphertext)    free(ctx->ciphertext);
    if (ctx->shared_secret) free(ctx->shared_secret);
    if (ctx->kem)            OQS_KEM_free((OQS_KEM *)ctx->kem);

    ctx->public_key = NULL;
    ctx->secret_key = NULL;
    ctx->ciphertext = NULL;
    ctx->shared_secret = NULL;
    ctx->kem = NULL;
    return 0;
}

size_t mlkem_get_public_key_len(mlkem_ctx_t *ctx)
{
    return ctx && ctx->kem ? ((OQS_KEM *)ctx->kem)->length_public_key : 0;
}

size_t mlkem_get_secret_key_len(mlkem_ctx_t *ctx)
{
    return ctx && ctx->kem ? ((OQS_KEM *)ctx->kem)->length_secret_key : 0;
}

size_t mlkem_get_ciphertext_len(mlkem_ctx_t *ctx)
{
    return ctx && ctx->kem ? ((OQS_KEM *)ctx->kem)->length_ciphertext : 0;
}

size_t mlkem_get_shared_secret_len(mlkem_ctx_t *ctx)
{
    return ctx && ctx->kem ? ((OQS_KEM *)ctx->kem)->length_shared_secret : 0;
}
