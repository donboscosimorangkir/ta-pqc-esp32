#include "mlkem768_mlkem.h"
#include "ml_kem/ml_kem_768.hpp"
#include "esp_random.h"
#include <array>
#include <span>
#include <cstring>
#include <cstdlib>

// Opaque C++ implementation struct
struct mlkem768_ctx_mlkem {
    // Seeds for key generation
    std::array<uint8_t, ml_kem_768::SEED_D_BYTE_LEN> seed_d;
    std::array<uint8_t, ml_kem_768::SEED_Z_BYTE_LEN> seed_z;
    std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> seed_m;
    
    // Keys and ciphertext
    std::array<uint8_t, ml_kem_768::PKEY_BYTE_LEN> pkey;
    std::array<uint8_t, ml_kem_768::SKEY_BYTE_LEN> skey;
    std::array<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN> cipher;
    std::array<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> shared_secret;
    
    // Spans for type-safe API
    std::span<const uint8_t, ml_kem_768::SEED_D_BYTE_LEN> d_span;
    std::span<const uint8_t, ml_kem_768::SEED_Z_BYTE_LEN> z_span;
    std::span<uint8_t, ml_kem_768::PKEY_BYTE_LEN> pkey_span;
    std::span<uint8_t, ml_kem_768::SKEY_BYTE_LEN> skey_span;
    std::span<const uint8_t, ml_kem_768::SEED_M_BYTE_LEN> m_span;
    std::span<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN> cipher_span;
    std::span<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> shared_secret_span;
    
    bool initialized;
    bool keypair_generated;
    
    mlkem768_ctx_mlkem() 
        : d_span(seed_d), z_span(seed_z), pkey_span(pkey), skey_span(skey),
          m_span(seed_m), cipher_span(cipher), shared_secret_span(shared_secret),
          initialized(false), keypair_generated(false)
    {
        seed_d.fill(0);
        seed_z.fill(0);
        seed_m.fill(0);
        pkey.fill(0);
        skey.fill(0);
        cipher.fill(0);
        shared_secret.fill(0);
    }
};

extern "C" {

int mlkem768_init(mlkem768_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return -1;
    }
    
    // Allocate C++ implementation
    mlkem768_ctx_mlkem *impl = new (std::nothrow) mlkem768_ctx_mlkem();
    if (impl == nullptr) {
        return -1;
    }
    ctx->impl = static_cast<void*>(impl);
    
    // Allocate buffers for C API compatibility
    ctx->public_key = (uint8_t*)malloc(MLKEM768_PUBLIC_KEY_LEN);
    ctx->secret_key = (uint8_t*)malloc(MLKEM768_SECRET_KEY_LEN);
    ctx->ciphertext = (uint8_t*)malloc(MLKEM768_CIPHERTEXT_LEN);
    ctx->shared_secret = (uint8_t*)malloc(MLKEM768_SHARED_SECRET_LEN);
    
    if (ctx->public_key == nullptr || ctx->secret_key == nullptr ||
        ctx->ciphertext == nullptr || ctx->shared_secret == nullptr) {
        mlkem768_cleanup(ctx);
        return -1;
    }
    
    impl->initialized = true;
    return 0;
}

int mlkem768_keypair(mlkem768_ctx_t *ctx)
{
    if (ctx == nullptr || ctx->impl == nullptr) {
        return -1;
    }
    
    mlkem768_ctx_mlkem *impl = static_cast<mlkem768_ctx_mlkem*>(ctx->impl);
    if (!impl->initialized) {
        return -1;
    }
    
    // Generate random seeds using ESP-IDF hardware RNG
    esp_fill_random(impl->seed_d.data(), impl->seed_d.size());
    esp_fill_random(impl->seed_z.data(), impl->seed_z.size());
    
    // Generate keypair using ml-kem
    ml_kem_768::keygen(impl->d_span, impl->z_span, 
                       impl->pkey_span, impl->skey_span);
    
    // Copy to C API buffers
    std::memcpy(ctx->public_key, impl->pkey.data(), MLKEM768_PUBLIC_KEY_LEN);
    std::memcpy(ctx->secret_key, impl->skey.data(), MLKEM768_SECRET_KEY_LEN);
    
    impl->keypair_generated = true;
    return 0;
}

int mlkem768_encaps(mlkem768_ctx_t *ctx, const uint8_t *public_key)
{
    if (ctx == nullptr || ctx->impl == nullptr) {
        return -1;
    }
    
    mlkem768_ctx_mlkem *impl = static_cast<mlkem768_ctx_mlkem*>(ctx->impl);
    if (!impl->initialized) {
        return -1;
    }
    
    // Use provided public key or the one from context
    const uint8_t *pkey_to_use = (public_key != nullptr) ? public_key : ctx->public_key;
    
    // Copy public key to internal buffer
    std::memcpy(impl->pkey.data(), pkey_to_use, MLKEM768_PUBLIC_KEY_LEN);
    
    // Generate random seed for encapsulation
    esp_fill_random(impl->seed_m.data(), impl->seed_m.size());
    
    // Encapsulate using ml-kem
    bool success = ml_kem_768::encapsulate(impl->m_span, impl->pkey_span,
                                            impl->cipher_span, impl->shared_secret_span);
    
    if (!success) {
        return -1;
    }
    
    // Copy to C API buffers
    std::memcpy(ctx->ciphertext, impl->cipher.data(), MLKEM768_CIPHERTEXT_LEN);
    std::memcpy(ctx->shared_secret, impl->shared_secret.data(), MLKEM768_SHARED_SECRET_LEN);
    
    return 0;
}

int mlkem768_decaps(mlkem768_ctx_t *ctx, const uint8_t *ciphertext)
{
    if (ctx == nullptr || ctx->impl == nullptr) {
        return -1;
    }
    
    mlkem768_ctx_mlkem *impl = static_cast<mlkem768_ctx_mlkem*>(ctx->impl);
    if (!impl->initialized || !impl->keypair_generated) {
        return -1;
    }
    
    // Use provided ciphertext or the one from context
    const uint8_t *cipher_to_use = (ciphertext != nullptr) ? ciphertext : ctx->ciphertext;
    
    // Copy ciphertext to internal buffer
    std::memcpy(impl->cipher.data(), cipher_to_use, MLKEM768_CIPHERTEXT_LEN);
    
    // Decapsulate using ml-kem
    ml_kem_768::decapsulate(impl->skey_span, impl->cipher_span,
                            impl->shared_secret_span);
    
    // Copy to C API buffer
    std::memcpy(ctx->shared_secret, impl->shared_secret.data(), MLKEM768_SHARED_SECRET_LEN);
    
    return 0;
}

int mlkem768_cleanup(mlkem768_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return -1;
    }
    
    // Free C++ implementation
    if (ctx->impl != nullptr) {
        mlkem768_ctx_mlkem *impl = static_cast<mlkem768_ctx_mlkem*>(ctx->impl);
        delete impl;
        ctx->impl = nullptr;
    }
    
    // Free C API buffers
    if (ctx->public_key != nullptr) {
        free(ctx->public_key);
        ctx->public_key = nullptr;
    }
    if (ctx->secret_key != nullptr) {
        free(ctx->secret_key);
        ctx->secret_key = nullptr;
    }
    if (ctx->ciphertext != nullptr) {
        free(ctx->ciphertext);
        ctx->ciphertext = nullptr;
    }
    if (ctx->shared_secret != nullptr) {
        free(ctx->shared_secret);
        ctx->shared_secret = nullptr;
    }
    
    return 0;
}

const char* mlkem768_get_algorithm_name(void)
{
    return "ML-KEM-768 (ml-kem C++20)";
}

size_t mlkem768_get_public_key_len(void)
{
    return ml_kem_768::PKEY_BYTE_LEN;
}

size_t mlkem768_get_secret_key_len(void)
{
    return ml_kem_768::SKEY_BYTE_LEN;
}

size_t mlkem768_get_ciphertext_len(void)
{
    return ml_kem_768::CIPHER_TEXT_BYTE_LEN;
}

size_t mlkem768_get_shared_secret_len(void)
{
    return ml_kem_768::SHARED_SECRET_BYTE_LEN;
}

} // extern "C"

