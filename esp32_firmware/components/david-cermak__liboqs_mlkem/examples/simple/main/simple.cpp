#include <cstdio>
#include <array>
#include <span>
#include "ml_kem/ml_kem_768.hpp"
#include "esp_random.h"
#include "esp_log.h"

#define TAG "simple"

extern "C" void app_main(void)
{
    ESP_LOGI(TAG, "ML-KEM-768 Example");

    // Seeds required for keypair generation
    std::array<uint8_t, ml_kem_768::SEED_D_BYTE_LEN> d{};
    std::array<uint8_t, ml_kem_768::SEED_Z_BYTE_LEN> z{};

    // Public/ private keypair
    std::array<uint8_t, ml_kem_768::PKEY_BYTE_LEN> pkey{};
    std::array<uint8_t, ml_kem_768::SKEY_BYTE_LEN> skey{};

    // Seed required for key encapsulation
    std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> m{};
    std::array<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN> cipher{};

    // Shared secrets that sender/ receiver arrive at
    std::array<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> sender_key{};
    std::array<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> receiver_key{};

    // Generate random seeds using ESP-IDF hardware RNG
    esp_fill_random(d.data(), d.size());
    esp_fill_random(z.data(), z.size());
    esp_fill_random(m.data(), m.size());

    // Create spans for type-safe API
    auto d_span = std::span<const uint8_t, ml_kem_768::SEED_D_BYTE_LEN>(d);
    auto z_span = std::span<const uint8_t, ml_kem_768::SEED_Z_BYTE_LEN>(z);
    auto pkey_span = std::span<uint8_t, ml_kem_768::PKEY_BYTE_LEN>(pkey);
    auto skey_span = std::span<uint8_t, ml_kem_768::SKEY_BYTE_LEN>(skey);
    auto m_span = std::span<const uint8_t, ml_kem_768::SEED_M_BYTE_LEN>(m);
    auto cipher_span = std::span<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN>(cipher);
    auto sender_key_span = std::span<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN>(sender_key);
    auto receiver_key_span = std::span<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN>(receiver_key);

    // Generate a keypair
    ESP_LOGI(TAG, "Generating ML-KEM-768 keypair...");
    ml_kem_768::keygen(d_span, z_span, pkey_span, skey_span);
    ESP_LOGI(TAG, "Keypair generated successfully");

    // Encapsulate key, compute cipher text and obtain shared secret
    ESP_LOGI(TAG, "Encapsulating shared secret...");
    const bool is_encapsulated = ml_kem_768::encapsulate(m_span, pkey_span, cipher_span, sender_key_span);
    if (!is_encapsulated) {
        ESP_LOGE(TAG, "Encapsulation failed!");
        return;
    }
    ESP_LOGI(TAG, "Encapsulation successful");

    // Decapsulate cipher text and obtain shared secret
    ESP_LOGI(TAG, "Decapsulating shared secret...");
    ml_kem_768::decapsulate(skey_span, cipher_span, receiver_key_span);
    ESP_LOGI(TAG, "Decapsulation successful");

    // Verify that both parties arrived at the same shared secret
    bool keys_match = true;
    for (size_t i = 0; i < sender_key.size(); i++) {
        if (sender_key[i] != receiver_key[i]) {
            keys_match = false;
            break;
        }
    }

    if (keys_match) {
        ESP_LOGI(TAG, "Shared secrets match! ML-KEM-768 operation successful.");
    } else {
        ESP_LOGE(TAG, "Shared secrets do not match! Operation failed.");
    }
}

