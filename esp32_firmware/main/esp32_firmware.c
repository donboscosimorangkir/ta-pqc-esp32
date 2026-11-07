#include <errno.h>
#include <string.h>
#include "esp_heap_caps.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_task_wdt.h"
#include "nvs_flash.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "cJSON.h"
#include "mlkem_generic.h"
#include "mldsa_generic.h"
#include "slhdsa_generic.h"
#include "hqc_component.h"
#include "ina219.h"
#include "wifi_config.h"

/* ================ KONFIGURASI - EDIT SESUAI KEBUTUHAN ================ */
#define SERVER_PORT      9000
#define N_TRIALS         10                /* trial per algoritma (KEM & ML-DSA) */
#define N_TRIALS_SLH     1                 /* trial per level SLH-DSA (sign sangat lambat) */
#define MAX_RETRY        2
#define SOCK_TIMEOUT_S   15
/* Stack task pengujian (byte). Kalau muncul "Stack canary watchpoint
 * triggered (pqc_task)" naikkan nilai ini (mis. 98304). */
#define PQC_TASK_STACK_BYTES 65536
/* ======================================================================= */

static const char *TAG = "PQC_MAIN";
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

typedef enum { FAM_MLKEM, FAM_HQC, FAM_MLDSA, FAM_SLHDSA } family_t;

typedef struct {
    family_t family;
    int level;             /* ML-KEM: 512/768/1024 | HQC: 1/3/5 | ML-DSA: 44/65/87 | SLH-DSA: 1/3/5 */
    const char *name;      /* nama untuk laporan & INIT ke server */
    int security_category; /* level NIST yang diklaim algoritma */
    int n_trials;          /* jumlah trial untuk konfigurasi ini */
} test_config_t;

static const test_config_t test_configs[] = {
    /* --- Key Establishment: dipasangkan pada level setara --- */
// DEBUG_OFF          { FAM_MLKEM,  512,  "ML-KEM-512",  1, N_TRIALS },
// DEBUG_OFF          { FAM_HQC,    1,    "HQC-1",       1, N_TRIALS },
// DEBUG_OFF     { FAM_MLKEM,  768,  "ML-KEM-768",  3, N_TRIALS },
// DEBUG_OFF     { FAM_HQC,    3,    "HQC-3",       3, N_TRIALS },
// DEBUG_OFF     { FAM_MLKEM,  1024, "ML-KEM-1024", 5, N_TRIALS },
// DEBUG_OFF     { FAM_HQC,    5,    "HQC-5",       5, N_TRIALS },
    /* --- Digital Signature --- */
// DEBUG_OFF     { FAM_MLDSA,  44,   "ML-DSA-44",   2, N_TRIALS },
// DEBUG_OFF     { FAM_MLDSA,  65,   "ML-DSA-65",   3, N_TRIALS },
// DEBUG_OFF     { FAM_MLDSA,  87,   "ML-DSA-87",   5, N_TRIALS },
{ FAM_SLHDSA, SLHDSA_LEVEL_1, "SLH-DSA-SHAKE-128s", 1, N_TRIALS_SLH },
{ FAM_SLHDSA, SLHDSA_LEVEL_3, "SLH-DSA-SHAKE-192s", 3, N_TRIALS_SLH },
{ FAM_SLHDSA, SLHDSA_LEVEL_5, "SLH-DSA-SHAKE-256s", 5, N_TRIALS_SLH },
};
#define N_CONFIGS (sizeof(test_configs) / sizeof(test_configs[0]))

/* ----------------- Energi (INA219) ----------------- */
static double g_idle_power_mw = -1.0;   /* baseline daya idle per konfigurasi */

static void add_energy(cJSON *rep, const char *key, const ina_result_t *r)
{
    if (!r->valid) return;

    double energy_net_mj = r->energy_mj;

    if (g_idle_power_mw >= 0.0 && r->duration_ms > 0.0) {
        double idle_energy_mj =
            g_idle_power_mw * (r->duration_ms / 1000.0);

        energy_net_mj -= idle_energy_mj;
    }

    cJSON_AddNumberToObject(rep, key, energy_net_mj);
}

static uint32_t min_samples3(const ina_result_t *a, const ina_result_t *b, const ina_result_t *c)
{
    uint32_t m = a->samples;
    if (b->samples < m) m = b->samples;
    if (c->samples < m) m = c->samples;
    return m;
}

static void add_energy_meta(cJSON *rep, uint32_t min_samples)
{
    cJSON_AddNumberToObject(rep, "ina_available", ina219_available() ? 1 : 0);
    if (ina219_available()) {
        cJSON_AddNumberToObject(rep, "energy_samples_min", min_samples);
        if (g_idle_power_mw >= 0) cJSON_AddNumberToObject(rep, "idle_power_mw", g_idle_power_mw);
    }
}

/* ----------------- WiFi ----------------- */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *disc =
            (wifi_event_sta_disconnected_t *)event_data;
        ESP_LOGW(TAG, "WiFi terputus. Alasan disconnect: %d", disc->reason);
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
        ESP_LOGI(TAG, "Dapat IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    ESP_LOGI(TAG, "Connecting to configured Wi-Fi network");
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    ESP_LOGI(TAG, "WiFi tersambung!");
}

/* ----------------- Socket framing helpers ----------------- */
static int recv_exact(int sock, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        int r = recv(sock, buf + got, n - got, 0);
        if (r <= 0) { ESP_LOGE("NET", "recv_exact r=%d errno=%d(%s) got=%u/%u", r, errno, strerror(errno), (unsigned)got, (unsigned)n); return -1; }
        got += r;
    }
    return 0;
}

static int recv_framed(int sock, uint8_t **out, uint32_t *out_len)
{
    uint8_t len_buf[4];
    if (recv_exact(sock, len_buf, 4) != 0) return -1;
    uint32_t len = ((uint32_t)len_buf[0] << 24) | ((uint32_t)len_buf[1] << 16) |
                   ((uint32_t)len_buf[2] << 8) | (uint32_t)len_buf[3];
    if (len == 0) { *out = NULL; *out_len = 0; return 0; }
    uint8_t *buf = malloc(len);
    if (!buf) return -1;
    if (recv_exact(sock, buf, len) != 0) { free(buf); return -1; }
    *out = buf;
    *out_len = len;
    return 0;
}

/* Kirim semua byte (loop), penting untuk signature SLH-DSA yang bisa ~30 KB. */
static int send_all(int sock, const uint8_t *data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int r = send(sock, data + sent, len - sent, 0);
        if (r <= 0) return -1;
        sent += r;
    }
    return 0;
}

static int send_framed(int sock, const uint8_t *data, uint32_t len)
{
    uint8_t len_buf[4] = { (len >> 24) & 0xFF, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF };
    if (send_all(sock, len_buf, 4) != 0) return -1;
    if (len > 0 && send_all(sock, data, len) != 0) return -1;
    return 0;
}

/* Hex-encode (untuk membandingkan shared secret dengan server). Caller free(). */
static char *hex_encode(const uint8_t *data, size_t len)
{
    static const char hexd[] = "0123456789abcdef";
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hexd[data[i] >> 4];
        out[i * 2 + 1] = hexd[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
    return out;
}

/* Buka koneksi ke server dan kirim INIT.
 * Return 0 jika berhasil (socket & waktu awal RTT diisi), -1 jika gagal
 * (socket sudah ditutup, caller cukup retry++). */
static int connect_and_init(const test_config_t *cfg, int trial_id, int retry,
                            int *out_sock, int64_t *out_t_rtt0)
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) { ESP_LOGE(TAG, "Gagal buat socket"); return -1; }

    struct timeval tv = { .tv_sec = SOCK_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &dest.sin_addr);

    *out_t_rtt0 = esp_timer_get_time();

    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        ESP_LOGW(TAG, "Trial %d [%s]: connect gagal, retry (%d/%d)", trial_id, cfg->name, retry + 1, MAX_RETRY);
        close(sock); vTaskDelay(pdMS_TO_TICKS(1000));
        return -1;
    }

    /* --- INIT --- */
    cJSON *init_json = cJSON_CreateObject();
    cJSON_AddStringToObject(init_json, "cmd", "INIT");
    cJSON_AddNumberToObject(init_json, "trial_id", trial_id);
    cJSON_AddStringToObject(init_json, "algorithm", cfg->name);
    if (cfg->family == FAM_MLKEM || cfg->family == FAM_HQC)
        cJSON_AddNumberToObject(init_json, "rounds", 2);  /* KEM dua ronde */
    char *init_str = cJSON_PrintUnformatted(init_json);
    int rc = send_framed(sock, (uint8_t *)init_str, strlen(init_str));
    free(init_str); cJSON_Delete(init_json);
    if (rc != 0) {
        ESP_LOGW(TAG, "Trial %d [%s]: kirim INIT gagal", trial_id, cfg->name);
        close(sock);
        return -1;
    }

    *out_sock = sock;
    return 0;
}

/* ----------------- Abstraksi KEM (ML-KEM & HQC) ----------------- */
typedef struct {
    bool         is_mlkem;
    mlkem_ctx_t  m;
    hqc_ctx_t    h;
} kem_session_t;

int hqc_oom_flag = 0;
static int kem_init_keypair(kem_session_t *x, const test_config_t *cfg)
{
    memset(x, 0, sizeof(*x));
    x->is_mlkem = (cfg->family == FAM_MLKEM);
    int rc;
    if (x->is_mlkem) {
        rc = mlkem_init(&x->m, cfg->level);
        if (rc == 0) rc = mlkem_keypair(&x->m);
    } else {
        rc = hqc_init(&x->h, cfg->level);
        hqc_oom_flag = 0;
        if (rc == 0) rc = hqc_keypair(&x->h);
        if (hqc_oom_flag) rc = -2;
    }
    return rc;
}

static int kem_encaps(kem_session_t *x, const uint8_t *pk)
{
    hqc_oom_flag = 0;
    int r = x->is_mlkem ? mlkem_encaps(&x->m, pk) : hqc_encaps(&x->h, pk);
    if (!x->is_mlkem && hqc_oom_flag) r = -2;
    return r;
}

static int kem_decaps(kem_session_t *x, const uint8_t *ct)
{
    hqc_oom_flag = 0;
    int r = x->is_mlkem ? mlkem_decaps(&x->m, ct) : hqc_decaps(&x->h, ct);
    if (!x->is_mlkem && hqc_oom_flag) r = -2;
    return r;
}

static const uint8_t *kem_pk(const kem_session_t *x)  { return x->is_mlkem ? x->m.public_key   : x->h.public_key; }
static const uint8_t *kem_ct(const kem_session_t *x)  { return x->is_mlkem ? x->m.ciphertext    : x->h.ciphertext; }
static const uint8_t *kem_ss(const kem_session_t *x)  { return x->is_mlkem ? x->m.shared_secret : x->h.shared_secret; }
static size_t kem_pk_len(kem_session_t *x) { return x->is_mlkem ? mlkem_get_public_key_len(&x->m)    : hqc_get_public_key_len(&x->h); }
static size_t kem_ct_len(kem_session_t *x) { return x->is_mlkem ? mlkem_get_ciphertext_len(&x->m)    : hqc_get_ciphertext_len(&x->h); }
static size_t kem_ss_len(kem_session_t *x) { return x->is_mlkem ? mlkem_get_shared_secret_len(&x->m) : hqc_get_shared_secret_len(&x->h); }

static void kem_cleanup(kem_session_t *x)
{
    if (x->is_mlkem) mlkem_cleanup(&x->m); else hqc_cleanup(&x->h);
}

/* ----------------- Satu trial KEM, DUA RONDE -----------------
 * Supaya KeyGen, Encaps, dan Decaps SEMUANYA terukur di ESP32:
 *   Ronde 1: ESP32 KeyGen -> kirim PK -> server Encaps -> ESP32 Decaps
 *   Ronde 2: peran ditukar. Server KeyGen -> kirim PK2 -> ESP32 Encaps
 *            -> kirim CT2 -> server Decaps
 * Shared secret kedua ronde dikirim (hex) agar server bisa memvalidasinya.
 * Context ronde 1 dipakai ulang untuk Encaps (buffer sudah teralokasi), jadi
 * pengukuran heap Encaps tidak bercampur dengan biaya alokasi.
 * Energi (INA219) diukur per operasi, hanya selama komputasi kripto. */
static bool run_trial_kem(const test_config_t *cfg, int trial_id)
{
    int retry = 0;
    bool success = false;

    while (retry <= MAX_RETRY && !success) {
        int sock; int64_t t_rtt0;
        if (connect_and_init(cfg, trial_id, retry, &sock, &t_rtt0) != 0) { retry++; continue; }

        kem_session_t kx;
        memset(&kx, 0, sizeof(kx));
        kx.is_mlkem = (cfg->family == FAM_MLKEM);
        uint8_t *ct = NULL, *meta_raw = NULL, *pk2 = NULL, *ack = NULL;
        uint32_t ct_len = 0, meta_len = 0, pk2_len = 0, ack_len = 0;
        char *ss1_hex = NULL, *ss2_hex = NULL;
        int dc_rc = -1, en_rc = -1;
        double keygen_ms = 0, decaps_ms = 0, encaps_ms = 0;
        uint32_t hb_kg = 0, ha_kg = 0, hb_dc = 0, ha_dc = 0, hb_en = 0, ha_en = 0;
        bool ok = false;
        ina_result_t e_kg = {0}, e_dc = {0}, e_en = {0};

        /* ===== RONDE 1: KeyGen + Decaps di ESP32 ===== */
        hb_kg = esp_get_free_heap_size();
        ina_measure_start();
        int64_t t0 = esp_timer_get_time();
        int kg_rc = kem_init_keypair(&kx, cfg);
        keygen_ms = (esp_timer_get_time() - t0) / 1000.0;
        ina_measure_stop(&e_kg);
        ha_kg = esp_get_free_heap_size();
        if (kg_rc != 0) {
            ESP_LOGE(TAG, "Trial %d [%s]: KeyGen gagal rc=%d free=%u largest=%u min=%u", trial_id, cfg->name, kg_rc, (unsigned)esp_get_free_heap_size(), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT), (unsigned)esp_get_minimum_free_heap_size());
            goto cleanup;
        }

        ESP_LOGI(TAG, "Trial %d [%s]: kirim PK len=%u keygen=%.1fms free=%u", trial_id, cfg->name, (unsigned)kem_pk_len(&kx), keygen_ms, (unsigned)esp_get_free_heap_size());
        if (send_framed(sock, kem_pk(&kx), (uint32_t)kem_pk_len(&kx)) != 0) {
            ESP_LOGW(TAG, "Trial %d [%s]: kirim PK gagal", trial_id, cfg->name);
            goto cleanup;
        }

        if (recv_framed(sock, &ct, &ct_len) != 0 || recv_framed(sock, &meta_raw, &meta_len) != 0 ||
            ct == NULL || ct_len != kem_ct_len(&kx)) {
            ESP_LOGW(TAG, "Trial %d [%s]: terima CT/meta gagal ct=%p ct_len=%u expect_ct=%u meta=%p meta_len=%u errno=%d(%s)", trial_id, cfg->name, (void *)ct, (unsigned)ct_len, (unsigned)kem_ct_len(&kx), (void *)meta_raw, (unsigned)meta_len, errno, strerror(errno));
            goto cleanup;
        }
        free(meta_raw); meta_raw = NULL;   /* metadata Encaps server (PC) dicatat server sendiri */

        hb_dc = esp_get_free_heap_size();
        ina_measure_start();
        t0 = esp_timer_get_time();
        dc_rc = kem_decaps(&kx, ct);
        decaps_ms = (esp_timer_get_time() - t0) / 1000.0;
        ina_measure_stop(&e_dc);
        ha_dc = esp_get_free_heap_size();
        ESP_LOGI("STACK", "[%s] setelah decaps: sisa stack min=%u B", cfg->name, (unsigned)uxTaskGetStackHighWaterMark(NULL));
        size_t ss_len = kem_ss_len(&kx);
        if (dc_rc == 0) ss1_hex = hex_encode(kem_ss(&kx), ss_len);   /* simpan sebelum Encaps menimpa */

        /* ===== RONDE 2: Encaps di ESP32 (peran ditukar) ===== */
        if (recv_framed(sock, &pk2, &pk2_len) != 0 || pk2 == NULL || pk2_len != kem_pk_len(&kx)) {
            ESP_LOGW(TAG, "Trial %d [%s]: terima PK ronde 2 gagal", trial_id, cfg->name);
            goto cleanup;
        }

        hb_en = esp_get_free_heap_size();
        ina_measure_start();
        t0 = esp_timer_get_time();
        en_rc = kem_encaps(&kx, pk2);
        encaps_ms = (esp_timer_get_time() - t0) / 1000.0;
        ina_measure_stop(&e_en);
        ha_en = esp_get_free_heap_size();
        ESP_LOGI("STACK", "[%s] setelah encaps: sisa stack min=%u B", cfg->name, (unsigned)uxTaskGetStackHighWaterMark(NULL));
        if (en_rc != 0) {
            ESP_LOGE(TAG, "Trial %d [%s]: Encaps gagal", trial_id, cfg->name);
            goto cleanup;
        }

        if (send_framed(sock, kem_ct(&kx), (uint32_t)kem_ct_len(&kx)) != 0) {
            ESP_LOGW(TAG, "Trial %d [%s]: kirim CT ronde 2 gagal", trial_id, cfg->name);
            goto cleanup;
        }
        ss2_hex = hex_encode(kem_ss(&kx), kem_ss_len(&kx));
        double network_rtt_ms = (esp_timer_get_time() - t_rtt0) / 1000.0;

        /* ===== REPORT ===== */
        ok = (dc_rc == 0 && en_rc == 0);
        cJSON *report = cJSON_CreateObject();
        cJSON_AddNumberToObject(report, "trial_id", trial_id);
        cJSON_AddStringToObject(report, "algorithm", cfg->name);
        cJSON_AddNumberToObject(report, "security_category", cfg->security_category);
        cJSON_AddNumberToObject(report, "keygen_time_ms", keygen_ms);
        cJSON_AddNumberToObject(report, "decaps_time_ms", decaps_ms);
        cJSON_AddNumberToObject(report, "encaps_time_ms", encaps_ms);   /* diukur di ESP32 (ronde 2) */
        cJSON_AddNumberToObject(report, "network_rtt_ms", network_rtt_ms);
        cJSON_AddNumberToObject(report, "heap_before_keygen", hb_kg);
        cJSON_AddNumberToObject(report, "heap_after_keygen", ha_kg);
        cJSON_AddNumberToObject(report, "heap_before_decaps", hb_dc);
        cJSON_AddNumberToObject(report, "heap_after_decaps", ha_dc);
        cJSON_AddNumberToObject(report, "heap_before_encaps", hb_en);
        cJSON_AddNumberToObject(report, "heap_after_encaps", ha_en);
        cJSON_AddNumberToObject(report, "ss_size_bytes", (double)ss_len);
        add_energy(report, "energy_keygen_mj", &e_kg);
        add_energy(report, "energy_decaps_mj", &e_dc);
        add_energy(report, "energy_encaps_mj", &e_en);
        add_energy_meta(report, min_samples3(&e_kg, &e_dc, &e_en));
        cJSON_AddStringToObject(report, "status", ok ? "success" : "fail");
        if (!ok) cJSON_AddStringToObject(report, "fail_reason", dc_rc != 0 ? "decaps_error" : "encaps_error");
        cJSON_AddNumberToObject(report, "retry_count", retry);
        if (ss1_hex) cJSON_AddStringToObject(report, "ss_hex", ss1_hex);
        if (ss2_hex) cJSON_AddStringToObject(report, "ss2_hex", ss2_hex);

        char *report_str = cJSON_PrintUnformatted(report);
        send_framed(sock, (uint8_t *)report_str, strlen(report_str));
        free(report_str); cJSON_Delete(report);

        recv_framed(sock, &ack, &ack_len);

        ESP_LOGI(TAG, "Trial %d [%s]: %s (keygen=%.3fms encaps=%.3fms decaps=%.3fms rtt=%.3fms)",
                 trial_id, cfg->name, ok ? "SUKSES" : "GAGAL",
                 keygen_ms, encaps_ms, decaps_ms, network_rtt_ms);

cleanup:
        free(ct); free(meta_raw); free(pk2); free(ack);
        free(ss1_hex); free(ss2_hex);
        kem_cleanup(&kx);
        close(sock);
        if (ok) success = true; else retry++;
    }
    return success;
}

/* ----------------- Abstraksi Signature (ML-DSA & SLH-DSA) ----------------- */
typedef struct {
    family_t     family;
    bool         inited;
    mldsa_ctx_t  m;
    slhdsa_ctx_t s;
} sig_session_t;

static int sig_init_keypair(sig_session_t *x, const test_config_t *cfg)
{
    memset(x, 0, sizeof(*x));
    x->family = cfg->family;
    int rc;
    if (cfg->family == FAM_SLHDSA) {
        rc = slhdsa_init(&x->s, cfg->level);
        if (rc == 0) { x->inited = true; rc = slhdsa_keypair(&x->s); }
    } else {
        rc = mldsa_init(&x->m, cfg->level);
        x->inited = true;
        if (rc == 0) rc = mldsa_keypair(&x->m);
    }
    return rc;
}

static int sig_sign(sig_session_t *x, const uint8_t *msg, size_t len)
{
    return (x->family == FAM_SLHDSA) ? slhdsa_sign(&x->s, msg, len)
                                     : mldsa_sign(&x->m, msg, len);
}

static int sig_verify(sig_session_t *x, const uint8_t *msg, size_t len)
{
    return (x->family == FAM_SLHDSA) ? slhdsa_verify(&x->s, msg, len, x->s.pk)
                                     : mldsa_verify(&x->m, msg, len, x->m.public_key);
}

static const uint8_t *sig_pk(const sig_session_t *x)
{
    return (x->family == FAM_SLHDSA) ? x->s.pk : x->m.public_key;
}

static size_t sig_pk_len(sig_session_t *x)
{
    return (x->family == FAM_SLHDSA) ? slhdsa_pk_len(&x->s)
                                     : mldsa_get_public_key_len(&x->m);
}

static const uint8_t *sig_sig(const sig_session_t *x)
{
    return (x->family == FAM_SLHDSA) ? x->s.sig : x->m.signature;
}

static size_t sig_sig_len(const sig_session_t *x)
{
    return (x->family == FAM_SLHDSA) ? x->s.sig_len : (size_t)x->m.signature_len;
}

static void sig_cleanup(sig_session_t *x)
{
    if (!x->inited) return;
    if (x->family == FAM_SLHDSA) slhdsa_cleanup(&x->s);
    else                         mldsa_cleanup(&x->m);
    x->inited = false;
}

/* ----------------- Satu trial Signature (KeyGen -> Sign -> Verify) -----------------
 * Ketiga operasi diukur di ESP32 (waktu, heap, energi). Verify juga dilakukan
 * independen oleh server (liboqs di PC) untuk memastikan hasil Sign kompatibel
 * dengan standar. */
static bool run_trial_sig(const test_config_t *cfg, int trial_id)
{
    int retry = 0;
    bool success = false;

    while (retry <= MAX_RETRY && !success) {
        int sock; int64_t t_rtt0;
        if (connect_and_init(cfg, trial_id, retry, &sock, &t_rtt0) != 0) { retry++; continue; }

        /* --- Terima pesan uji dari server --- */
        uint8_t *msg = NULL; uint32_t msg_len = 0;
        if (recv_framed(sock, &msg, &msg_len) != 0 || msg == NULL || msg_len == 0) {
            ESP_LOGW(TAG, "Trial %d [%s]: terima pesan uji gagal", trial_id, cfg->name);
            close(sock); free(msg);
            retry++; continue;
        }

        /* --- KeyGen --- */
        sig_session_t sx;
        ina_result_t e_kg = {0}, e_sg = {0}, e_vf = {0};
        uint32_t heap_before_keygen = esp_get_free_heap_size();
        ina_measure_start();
        int64_t t0 = esp_timer_get_time();
        int kg_rc = sig_init_keypair(&sx, cfg);
        double keygen_ms = (esp_timer_get_time() - t0) / 1000.0;
        ina_measure_stop(&e_kg);
        uint32_t heap_after_keygen = esp_get_free_heap_size();
        ESP_LOGI("STACK", "[%s] setelah keygen: sisa stack min=%u B", cfg->name, (unsigned)uxTaskGetStackHighWaterMark(NULL));

        if (kg_rc != 0) {
            ESP_LOGE(TAG, "Trial %d [%s]: KeyGen gagal (rc=%d)", trial_id, cfg->name, kg_rc);
            free(msg); close(sock); sig_cleanup(&sx);
            retry++; continue;
        }

        /* --- Sign --- */
        uint32_t heap_before_sign = esp_get_free_heap_size();
        ina_measure_start();
        t0 = esp_timer_get_time();
        int sg_rc = sig_sign(&sx, msg, msg_len);
        double sign_ms = (esp_timer_get_time() - t0) / 1000.0;
        ina_measure_stop(&e_sg);
        uint32_t heap_after_sign = esp_get_free_heap_size();
        ESP_LOGI("STACK", "[%s] setelah sign: sisa stack min=%u B", cfg->name, (unsigned)uxTaskGetStackHighWaterMark(NULL));

        if (sg_rc != 0) {
            ESP_LOGE(TAG, "Trial %d [%s]: Sign gagal (rc=%d)", trial_id, cfg->name, sg_rc);
            free(msg); close(sock); sig_cleanup(&sx);
            retry++; continue;
        }

        /* --- Verify lokal (diukur di ESP32) --- */
        ina_measure_start();
        t0 = esp_timer_get_time();
        int vf_rc = sig_verify(&sx, msg, msg_len);
        double verify_ms = (esp_timer_get_time() - t0) / 1000.0;
        ina_measure_stop(&e_vf);

        /* --- Kirim Public Key + Signature ke server --- */
        size_t pk_len  = sig_pk_len(&sx);
        size_t sig_len = sig_sig_len(&sx);
        if (send_framed(sock, sig_pk(&sx), (uint32_t)pk_len) != 0 ||
            send_framed(sock, sig_sig(&sx), (uint32_t)sig_len) != 0) {
            ESP_LOGW(TAG, "Trial %d [%s]: kirim PK/signature gagal", trial_id, cfg->name);
            free(msg); close(sock); sig_cleanup(&sx);
            retry++; continue;
        }

        /* --- Terima hasil verify dari server --- */
        uint8_t *meta_raw = NULL; uint32_t meta_len = 0;
        if (recv_framed(sock, &meta_raw, &meta_len) != 0) {
            ESP_LOGW(TAG, "Trial %d [%s]: terima metadata verify gagal", trial_id, cfg->name);
            free(msg); free(meta_raw); close(sock); sig_cleanup(&sx);
            retry++; continue;
        }
        bool server_ok = false;
        cJSON *meta_json = cJSON_ParseWithLength((char *)meta_raw, meta_len);
        if (meta_json) {
            server_ok = cJSON_IsTrue(cJSON_GetObjectItem(meta_json, "verify_ok"));
            cJSON_Delete(meta_json);
        }
        free(meta_raw);

        bool ok = (vf_rc == 0) && server_ok;
        double network_rtt_ms = (esp_timer_get_time() - t_rtt0) / 1000.0;

        /* --- Susun REPORT --- */
        cJSON *report = cJSON_CreateObject();
        cJSON_AddNumberToObject(report, "trial_id", trial_id);
        cJSON_AddStringToObject(report, "algorithm", cfg->name);
        cJSON_AddNumberToObject(report, "security_category", cfg->security_category);
        cJSON_AddNumberToObject(report, "keygen_time_ms", keygen_ms);
        cJSON_AddNumberToObject(report, "sign_time_ms", sign_ms);
        cJSON_AddNumberToObject(report, "verify_time_ms", verify_ms);
        cJSON_AddNumberToObject(report, "network_rtt_ms", network_rtt_ms);
        cJSON_AddNumberToObject(report, "heap_before_keygen", heap_before_keygen);
        cJSON_AddNumberToObject(report, "heap_after_keygen", heap_after_keygen);
        cJSON_AddNumberToObject(report, "heap_before_sign", heap_before_sign);
        cJSON_AddNumberToObject(report, "heap_after_sign", heap_after_sign);
        cJSON_AddNumberToObject(report, "sig_size_bytes", (double)sig_len);
        add_energy(report, "energy_keygen_mj", &e_kg);
        add_energy(report, "energy_sign_mj", &e_sg);
        add_energy(report, "energy_verify_mj", &e_vf);
        add_energy_meta(report, min_samples3(&e_kg, &e_sg, &e_vf));
        cJSON_AddStringToObject(report, "status", ok ? "success" : "fail");
        if (!ok) {
            cJSON_AddStringToObject(report, "fail_reason",
                                    vf_rc != 0 ? "local_verify_failed" : "server_verify_failed");
        }
        cJSON_AddNumberToObject(report, "retry_count", retry);

        char *report_str = cJSON_PrintUnformatted(report);
        send_framed(sock, (uint8_t *)report_str, strlen(report_str));
        free(report_str); cJSON_Delete(report);

        uint8_t *ack = NULL; uint32_t ack_len = 0;
        recv_framed(sock, &ack, &ack_len);
        free(ack);

        ESP_LOGI(TAG, "Trial %d [%s]: %s (keygen=%.3fms sign=%.3fms verify=%.3fms sig=%u B rtt=%.3fms)",
                 trial_id, cfg->name, ok ? "SUKSES" : "GAGAL",
                 keygen_ms, sign_ms, verify_ms, (unsigned)sig_len, network_rtt_ms);

        free(msg);
        sig_cleanup(&sx);
        close(sock);
        success = ok;
        if (!success) retry++;
    }
    return success;
}

static bool run_trial(const test_config_t *cfg, int trial_id)
{
    if (cfg->family == FAM_MLDSA || cfg->family == FAM_SLHDSA) return run_trial_sig(cfg, trial_id);
    return run_trial_kem(cfg, trial_id);
}

/* ----------------- Task utama ----------------- */
static void pqc_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Mulai pengujian: %d konfigurasi algoritma", (int)N_CONFIGS);

    for (size_t c = 0; c < N_CONFIGS; c++) {
        const test_config_t *cfg = &test_configs[c];
        int success_count = 0;

        /* Baseline daya idle (sampler aktif) untuk menghitung energi bersih. */
        g_idle_power_mw = ina219_available() ? ina_measure_idle_power_mw(500) : -1.0;
        if (g_idle_power_mw >= 0) ESP_LOGI(TAG, "%s: daya idle %.1f mW", cfg->name, g_idle_power_mw);

        for (int i = 1; i <= cfg->n_trials; i++) {
            if (run_trial(cfg, i)) success_count++;
            vTaskDelay(pdMS_TO_TICKS(200));
        }
        ESP_LOGI(TAG, "%s selesai: %d/%d sukses", cfg->name, success_count, cfg->n_trials);
    }

    ESP_LOGI(TAG, "=== SEMUA TRIAL SELESAI ===");
    vTaskDelete(NULL);
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init_sta();

    /* INA219 untuk pengukuran energi. Jika tidak terdeteksi, energi
     * dinonaktifkan dan pengujian tetap berjalan seperti biasa. */
    ina219_init();

    /* SLH-DSA sign berjalan puluhan detik s.d. menit tanpa yield, sehingga
     * idle task kelaparan dan Task Watchdog menembak. Matikan TWDT selama
     * pengujian (abaikan hasilnya kalau sudah nonaktif). */
    esp_err_t wr = esp_task_wdt_deinit();
    ESP_LOGI(TAG, "esp_task_wdt_deinit: %s", esp_err_to_name(wr));

    /* Stack besar wajib untuk operasi PQC - default 8KB tidak cukup.
     * Dipasang di core 1 supaya sampling INA219 (esp_timer, core 0) tidak
     * memotong operasi kripto dan menggelembungkan waktu eksekusi. */
    {
        static const uint32_t stk[] = { 65536, 57344, 49152 };
        BaseType_t ok = pdFAIL;
        for (int i = 0; i < 3 && ok != pdPASS; i++) {
            ok = xTaskCreatePinnedToCore(pqc_task, "pqc_task", stk[i], NULL, 5, NULL, 1);
            ESP_LOGI("STACK", "pqc_task stack=%u -> %s free=%u largest=%u", (unsigned)stk[i],
                     ok == pdPASS ? "OK" : "GAGAL", (unsigned)esp_get_free_heap_size(),
                     (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
        }
    }
}
