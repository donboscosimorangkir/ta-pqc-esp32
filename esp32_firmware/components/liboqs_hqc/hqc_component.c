#include "hqc_component.h"

#include <oqs/oqs.h>
#include "esp_log.h"
#include <stdlib.h>
#include <string.h>

/* Wrapper HQC dipanggil langsung: OQS_KEM_new() milik komponen liboqs_mlkem
 * tidak mengenal nama "HQC-1/3/5". */
extern OQS_KEM *OQS_KEM_hqc_1_new(void);
extern OQS_KEM *OQS_KEM_hqc_3_new(void);
extern OQS_KEM *OQS_KEM_hqc_5_new(void);

static OQS_KEM *hqc_kem_new(int level)
{
    switch (level) {
        case 1: return OQS_KEM_hqc_1_new();
        case 3: return OQS_KEM_hqc_3_new();
        case 5: return OQS_KEM_hqc_5_new();
        default: return NULL;
    }
}


int hqc_init(hqc_ctx_t *ctx, int level)
{
    if (!ctx) {
        return -1;
    }

    const char *algorithm = NULL;

    switch (level) {
        case 1:
            algorithm = "HQC-1";
            break;

        case 3:
            algorithm = "HQC-3";
            break;

        case 5:
            algorithm = "HQC-5";
            break;

        default:
            return -1;
    }

    memset(ctx, 0, sizeof(*ctx));

    (void)algorithm;
    OQS_KEM *kem = hqc_kem_new(level);
    if (!kem) {
        ESP_LOGE("HQC", "OQS_KEM_new(\"%s\") NULL: algoritma tidak aktif di build liboqs", algorithm);
        return -1;
    }

    ctx->kem = kem;

    ctx->public_key = malloc(kem->length_public_key);
    ctx->secret_key = malloc(kem->length_secret_key);
    ctx->ciphertext = malloc(kem->length_ciphertext);
    ctx->shared_secret = malloc(kem->length_shared_secret);

    if (!ctx->public_key ||
        !ctx->secret_key ||
        !ctx->ciphertext ||
        !ctx->shared_secret) {

        ESP_LOGE("HQC", "malloc gagal pk=%p sk=%p ct=%p ss=%p",
                 (void *)ctx->public_key, (void *)ctx->secret_key,
                 (void *)ctx->ciphertext, (void *)ctx->shared_secret);
        hqc_cleanup(ctx);
        return -1;
    }

    return 0;
}

int hqc_keypair(hqc_ctx_t *ctx)
{
    if (!ctx || !ctx->kem) {
        return -1;
    }

    OQS_KEM *kem = (OQS_KEM *)ctx->kem;

    return (kem->keypair(
        ctx->public_key,
        ctx->secret_key
    ) == OQS_SUCCESS) ? 0 : -1;
}

int hqc_encaps(hqc_ctx_t *ctx, const uint8_t *public_key)
{
    if (!ctx || !ctx->kem || !public_key) {
        return -1;
    }

    OQS_KEM *kem = (OQS_KEM *)ctx->kem;

    return (kem->encaps(
        ctx->ciphertext,
        ctx->shared_secret,
        public_key
    ) == OQS_SUCCESS) ? 0 : -1;
}

int hqc_decaps(hqc_ctx_t *ctx, const uint8_t *ciphertext)
{
    if (!ctx || !ctx->kem || !ciphertext) {
        return -1;
    }

    OQS_KEM *kem = (OQS_KEM *)ctx->kem;

    return (kem->decaps(
        ctx->shared_secret,
        ciphertext,
        ctx->secret_key
    ) == OQS_SUCCESS) ? 0 : -1;
}

int hqc_cleanup(hqc_ctx_t *ctx)
{
    if (!ctx) {
        return -1;
    }

    free(ctx->public_key);
    free(ctx->secret_key);
    free(ctx->ciphertext);
    free(ctx->shared_secret);

    if (ctx->kem) {
        OQS_KEM_free((OQS_KEM *)ctx->kem);
    }

    memset(ctx, 0, sizeof(*ctx));

    return 0;
}

size_t hqc_get_public_key_len(hqc_ctx_t *ctx)
{
    return ((OQS_KEM *)ctx->kem)->length_public_key;
}

size_t hqc_get_secret_key_len(hqc_ctx_t *ctx)
{
    return ((OQS_KEM *)ctx->kem)->length_secret_key;
}

size_t hqc_get_ciphertext_len(hqc_ctx_t *ctx)
{
    return ((OQS_KEM *)ctx->kem)->length_ciphertext;
}

size_t hqc_get_shared_secret_len(hqc_ctx_t *ctx)
{
    return ((OQS_KEM *)ctx->kem)->length_shared_secret;
}
