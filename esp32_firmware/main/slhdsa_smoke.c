#include <stdio.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "slhdsa_generic.h"

#define SLH_TASK_STACK 32768

static void slhdsa_smoke_task(void *arg)
{
    int level = (int)(intptr_t)arg;
    slhdsa_ctx_t c;
    const uint8_t msg[] = "SLH-DSA smoke test ESP32";

    printf("[SLH] heap bebas sebelum init : %u B\n",
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));

    int rc = slhdsa_init(&c, level);
    printf("[SLH] init level %d rc=%d (%s)\n", level, rc, rc == 0 ? slhdsa_name(&c) : "gagal");
    if (rc != 0) goto done;

    int64_t t0 = esp_timer_get_time();
    rc = slhdsa_keypair(&c);
    int64_t t1 = esp_timer_get_time();
    printf("[SLH] keypair rc=%d  %lld us\n", rc, (long long)(t1 - t0));
    if (rc != 0) goto cleanup;

    rc = slhdsa_sign(&c, msg, sizeof(msg));
    int64_t t2 = esp_timer_get_time();
    printf("[SLH] sign    rc=%d  %lld us  sig=%u B\n",
           rc, (long long)(t2 - t1), (unsigned)slhdsa_sig_len(&c));
    if (rc != 0) goto cleanup;

    rc = slhdsa_verify(&c, msg, sizeof(msg), NULL);
    int64_t t3 = esp_timer_get_time();
    printf("[SLH] verify  rc=%d  %lld us  (harus 0)\n", rc, (long long)(t3 - t2));

    c.sig[0] ^= 0x01;   /* rusak 1 bit -> harus ditolak */
    rc = slhdsa_verify(&c, msg, sizeof(msg), NULL);
    printf("[SLH] verify sig rusak rc=%d (harus %d)\n", rc, SLHDSA_ERR_VERIFY);

    printf("[SLH] stack terpakai maks     : %u B dari %d B\n",
           (unsigned)(SLH_TASK_STACK - uxTaskGetStackHighWaterMark(NULL)), SLH_TASK_STACK);
    printf("[SLH] heap bebas minimum      : %u B\n",
           (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT));

cleanup:
    slhdsa_cleanup(&c);
done:
    printf("[SLH] selesai\n");
    vTaskDelete(NULL);
}

/* Panggil dari app_main: slhdsa_smoke_start(1);  (1 / 3 / 5) */
void slhdsa_smoke_start(int level)
{
    /* dipin ke core 1 supaya WiFi (core 0) tidak terganggu */
    xTaskCreatePinnedToCore(slhdsa_smoke_task, "slh_smoke", SLH_TASK_STACK,
                            (void *)(intptr_t)level, 5, NULL, 1);
}
