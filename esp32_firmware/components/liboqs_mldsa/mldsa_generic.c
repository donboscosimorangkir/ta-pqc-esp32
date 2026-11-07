#include "mldsa_generic.h"
#include <oqs/oqs.h>
#include <oqs/sig.h>
#include <stdlib.h>

/* Deklarasi langsung ke constructor per-level (menghindari dispatcher
 * generic OQS_SIG_new, yang menyeret puluhan algoritma sig lain yang
 * tidak kita butuhkan/porting) */
extern OQS_SIG *OQS_SIG_ml_dsa_44_new(void);
extern OQS_SIG *OQS_SIG_ml_dsa_65_new(void);
extern OQS_SIG *OQS_SIG_ml_dsa_87_new(void);

/* Wrapper tipis pengganti OQS_SIG_keypair/sign/verify/free dari sig.c
 * (yang sudah kita buang bersama OQS_SIG_new). Semantiknya identik
 * dengan versi asli liboqs: cuma memanggil function pointer di struct. */
static OQS_STATUS local_sig_keypair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key)
{
    if (sig == NULL || sig->keypair == NULL) return OQS_ERROR;
    return sig->keypair(public_key, secret_key);
}

static OQS_STATUS local_sig_sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len,
                                 const uint8_t *message, size_t message_len, const uint8_t *secret_key)
{
    if (sig == NULL || sig->sign == NULL) return OQS_ERROR;
    return sig->sign(signature, signature_len, message, message_len, secret_key);
}

static OQS_STATUS local_sig_verify(const OQS_SIG *sig, const uint8_t *message, size_t message_len,
                                   const uint8_t *signature, size_t signature_len, const uint8_t *public_key)
{
    if (sig == NULL || sig->verify == NULL) return OQS_ERROR;
    return sig->verify(message, message_len, signature, signature_len, public_key);
}

static void local_sig_free(OQS_SIG *sig)
{
    if (sig != NULL) free(sig);
}

int mldsa_init(mldsa_ctx_t *ctx, int level)
{
    if (ctx == NULL) return -1;

    OQS_init();

    OQS_SIG *sig;
    switch (level) {
        case 44: sig = OQS_SIG_ml_dsa_44_new(); break;
        case 65: sig = OQS_SIG_ml_dsa_65_new(); break;
        case 87: sig = OQS_SIG_ml_dsa_87_new(); break;
        default: return -1;
    }
    if (sig == NULL) return -1;
    ctx->sig = sig;

    ctx->public_key = malloc(sig->length_public_key);
    ctx->secret_key = malloc(sig->length_secret_key);
    ctx->signature  = malloc(sig->length_signature);
    ctx->signature_len = 0;

    if (!ctx->public_key || !ctx->secret_key || !ctx->signature) {
        mldsa_cleanup(ctx);
        return -1;
    }
    return 0;
}

int mldsa_keypair(mldsa_ctx_t *ctx)
{
    if (ctx == NULL || ctx->sig == NULL) return -1;
    OQS_SIG *sig = (OQS_SIG *)ctx->sig;
    return (local_sig_keypair(sig, ctx->public_key, ctx->secret_key) == OQS_SUCCESS) ? 0 : -1;
}

int mldsa_sign(mldsa_ctx_t *ctx, const uint8_t *message, size_t message_len)
{
    if (ctx == NULL || ctx->sig == NULL || message == NULL) return -1;
    OQS_SIG *sig = (OQS_SIG *)ctx->sig;
    return (local_sig_sign(sig, ctx->signature, &ctx->signature_len, message, message_len, ctx->secret_key) == OQS_SUCCESS) ? 0 : -1;
}

int mldsa_verify(mldsa_ctx_t *ctx, const uint8_t *message, size_t message_len, const uint8_t *public_key)
{
    if (ctx == NULL || ctx->sig == NULL || message == NULL || public_key == NULL) return -1;
    OQS_SIG *sig = (OQS_SIG *)ctx->sig;
    return (local_sig_verify(sig, message, message_len, ctx->signature, ctx->signature_len, public_key) == OQS_SUCCESS) ? 0 : -1;
}

int mldsa_cleanup(mldsa_ctx_t *ctx)
{
    if (ctx == NULL) return 0;
    if (ctx->public_key) free(ctx->public_key);
    if (ctx->secret_key) free(ctx->secret_key);
    if (ctx->signature)  free(ctx->signature);
    if (ctx->sig)         local_sig_free((OQS_SIG *)ctx->sig);

    ctx->public_key = NULL;
    ctx->secret_key = NULL;
    ctx->signature = NULL;
    ctx->signature_len = 0;
    ctx->sig = NULL;
    return 0;
}

size_t mldsa_get_public_key_len(mldsa_ctx_t *ctx)
{
    return ctx && ctx->sig ? ((OQS_SIG *)ctx->sig)->length_public_key : 0;
}

size_t mldsa_get_secret_key_len(mldsa_ctx_t *ctx)
{
    return ctx && ctx->sig ? ((OQS_SIG *)ctx->sig)->length_secret_key : 0;
}

size_t mldsa_get_max_signature_len(mldsa_ctx_t *ctx)
{
    return ctx && ctx->sig ? ((OQS_SIG *)ctx->sig)->length_signature : 0;
}
