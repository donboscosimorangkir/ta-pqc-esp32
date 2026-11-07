/*
 * slhdsa_generic.c
 * Memanggil slh_keygen / slh_sign / slh_verify langsung (tanpa wrapper OQS_SIG_*).
 * Perilaku sama dengan wrapper liboqs "pure": ctx kosong, sign hedged (addrnd acak).
 */
#include <stdlib.h>
#include <string.h>

#include "esp_random.h"

#include "slhdsa_generic.h"
#include "slh_dsa.h"

typedef struct {
    int                level;
    const slh_param_t *prm;
    const char        *name;
    size_t             pk_len;
    size_t             sk_len;
    size_t             sig_len;
} slhdsa_info_t;

static const slhdsa_info_t *slhdsa_lookup(int level)
{
    static const slhdsa_info_t t1 = { 1, &slh_dsa_shake_128s, "SLH-DSA-SHAKE-128s", 32,  64,  7856  };
    static const slhdsa_info_t t3 = { 3, &slh_dsa_shake_192s, "SLH-DSA-SHAKE-192s", 48,  96,  16224 };
    static const slhdsa_info_t t5 = { 5, &slh_dsa_shake_256s, "SLH-DSA-SHAKE-256s", 64,  128, 29792 };

    switch (level) {
    case 1: case 128: return &t1;
    case 3: case 192: return &t3;
    case 5: case 256: return &t5;
    default:          return NULL;
    }
}

/* konvensi sama dengan wrapper liboqs: return 0 = sukses */
static int slhdsa_rbg(uint8_t *x, size_t xlen)
{
    esp_fill_random(x, xlen);
    return 0;
}

static void secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

int slhdsa_init(slhdsa_ctx_t *ctx, int level)
{
    if (ctx == NULL) return SLHDSA_ERR_PARAM;

    const slhdsa_info_t *inf = slhdsa_lookup(level);
    memset(ctx, 0, sizeof(*ctx));
    if (inf == NULL) return SLHDSA_ERR_PARAM;

    ctx->level       = inf->level;
    ctx->prm         = inf->prm;
    ctx->name        = inf->name;
    ctx->pk_len      = inf->pk_len;
    ctx->sk_len      = inf->sk_len;
    ctx->sig_max_len = inf->sig_len;

    ctx->pk  = (uint8_t *)malloc(ctx->pk_len);
    ctx->sk  = (uint8_t *)malloc(ctx->sk_len);
    ctx->sig = (uint8_t *)malloc(ctx->sig_max_len);

    if (!ctx->pk || !ctx->sk || !ctx->sig) {
        slhdsa_cleanup(ctx);
        return SLHDSA_ERR_NOMEM;
    }
    return SLHDSA_OK;
}

int slhdsa_keypair(slhdsa_ctx_t *ctx)
{
    if (ctx == NULL || ctx->prm == NULL) return SLHDSA_ERR_STATE;

    int rc = slh_keygen(ctx->sk, ctx->pk, slhdsa_rbg, (const slh_param_t *)ctx->prm);
    if (rc != 0) {
        ctx->has_keys = 0;
        return SLHDSA_ERR_KEYGEN;
    }
    ctx->has_keys = 1;
    ctx->has_sig  = 0;
    return SLHDSA_OK;
}

int slhdsa_sign(slhdsa_ctx_t *ctx, const uint8_t *msg, size_t len)
{
    if (ctx == NULL || ctx->prm == NULL || (msg == NULL && len > 0)) return SLHDSA_ERR_PARAM;
    if (!ctx->has_keys) return SLHDSA_ERR_STATE;

    uint8_t addrnd[32];                 /* n = 16/24/32, 32 cukup untuk semua level */
    esp_fill_random(addrnd, sizeof(addrnd));

    size_t n = slh_sign(ctx->sig, msg, len, NULL, 0, ctx->sk, addrnd,
                        (const slh_param_t *)ctx->prm);
    secure_zero(addrnd, sizeof(addrnd));

    if (n == 0 || n > ctx->sig_max_len) {
        ctx->has_sig = 0;
        ctx->sig_len = 0;
        return SLHDSA_ERR_SIGN;
    }
    ctx->sig_len = n;
    ctx->has_sig = 1;
    return SLHDSA_OK;
}

int slhdsa_verify(slhdsa_ctx_t *ctx, const uint8_t *msg, size_t len, const uint8_t *pk)
{
    if (ctx == NULL || ctx->prm == NULL || (msg == NULL && len > 0)) return SLHDSA_ERR_PARAM;
    if (!ctx->has_sig) return SLHDSA_ERR_STATE;
    if (pk == NULL) pk = ctx->pk;

    /* slh_verify: nonzero = valid */
    int ok = slh_verify(msg, len, ctx->sig, ctx->sig_len, NULL, 0, pk,
                        (const slh_param_t *)ctx->prm);
    return ok ? SLHDSA_OK : SLHDSA_ERR_VERIFY;
}

void slhdsa_cleanup(slhdsa_ctx_t *ctx)
{
    if (ctx == NULL) return;
    if (ctx->sk) { secure_zero(ctx->sk, ctx->sk_len); free(ctx->sk); }
    free(ctx->pk);
    free(ctx->sig);
    memset(ctx, 0, sizeof(*ctx));
}

size_t      slhdsa_pk_len(const slhdsa_ctx_t *ctx)      { return ctx ? ctx->pk_len : 0; }
size_t      slhdsa_sk_len(const slhdsa_ctx_t *ctx)      { return ctx ? ctx->sk_len : 0; }
size_t      slhdsa_sig_max_len(const slhdsa_ctx_t *ctx) { return ctx ? ctx->sig_max_len : 0; }
size_t      slhdsa_sig_len(const slhdsa_ctx_t *ctx)     { return ctx ? ctx->sig_len : 0; }
const char *slhdsa_name(const slhdsa_ctx_t *ctx)        { return ctx ? ctx->name : NULL; }
