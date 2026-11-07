/*
 * slhdsa_generic.h - API generik SLH-DSA-SHAKE (FIPS 205, varian "s")
 *   Level 1 -> SLH-DSA-SHAKE-128s  (pk 32,  sk 64,  sig 7856)
 *   Level 3 -> SLH-DSA-SHAKE-192s  (pk 48,  sk 96,  sig 16224)
 *   Level 5 -> SLH-DSA-SHAKE-256s  (pk 64,  sk 128, sig 29792)
 */
#ifndef SLHDSA_GENERIC_H
#define SLHDSA_GENERIC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SLHDSA_LEVEL_1 1
#define SLHDSA_LEVEL_3 3
#define SLHDSA_LEVEL_5 5

/* 0 = sukses, negatif = gagal */
#define SLHDSA_OK            0
#define SLHDSA_ERR_PARAM    (-1)
#define SLHDSA_ERR_NOMEM    (-2)
#define SLHDSA_ERR_KEYGEN   (-3)
#define SLHDSA_ERR_SIGN     (-4)
#define SLHDSA_ERR_VERIFY   (-5)
#define SLHDSA_ERR_STATE    (-6)

#define SLHDSA_MAX_PK_LEN   64
#define SLHDSA_MAX_SK_LEN   128
#define SLHDSA_MAX_SIG_LEN  29792

typedef struct {
    int         level;
    const void *prm;            /* slh_param_t* (opaque) */
    const char *name;

    size_t      pk_len;
    size_t      sk_len;
    size_t      sig_max_len;

    uint8_t    *pk;
    uint8_t    *sk;
    uint8_t    *sig;
    size_t      sig_len;

    int         has_keys;
    int         has_sig;
} slhdsa_ctx_t;

int  slhdsa_init(slhdsa_ctx_t *ctx, int level);
int  slhdsa_keypair(slhdsa_ctx_t *ctx);
int  slhdsa_sign(slhdsa_ctx_t *ctx, const uint8_t *msg, size_t len);
/* pk == NULL -> pakai ctx->pk. Return SLHDSA_OK jika valid. */
int  slhdsa_verify(slhdsa_ctx_t *ctx, const uint8_t *msg, size_t len, const uint8_t *pk);
void slhdsa_cleanup(slhdsa_ctx_t *ctx);

size_t      slhdsa_pk_len(const slhdsa_ctx_t *ctx);
size_t      slhdsa_sk_len(const slhdsa_ctx_t *ctx);
size_t      slhdsa_sig_max_len(const slhdsa_ctx_t *ctx);
size_t      slhdsa_sig_len(const slhdsa_ctx_t *ctx);
const char *slhdsa_name(const slhdsa_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SLHDSA_GENERIC_H */
