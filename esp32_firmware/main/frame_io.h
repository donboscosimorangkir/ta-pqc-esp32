#pragma once
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_heap_caps.h"

#define NET_TAG "NET"

#define HEAP_LOG(tag) ESP_LOGI("HEAP", "%s free=%u largest=%u min=%u", (tag), \
    (unsigned)esp_get_free_heap_size(), \
    (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT), \
    (unsigned)esp_get_minimum_free_heap_size())

static inline int send_all(int s, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = send(s, buf + off, len - off, 0);
        if (n < 0) {
            ESP_LOGE(NET_TAG, "send errno=%d (%s) off=%u/%u", errno, strerror(errno),
                     (unsigned)off, (unsigned)len);
            return -1;
        }
        if (n == 0) { ESP_LOGE(NET_TAG, "send 0 byte"); return -1; }
        off += (size_t)n;
    }
    return 0;
}

static inline int recv_all(int s, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = recv(s, buf + off, len - off, 0);
        if (n < 0) {
            ESP_LOGE(NET_TAG, "recv errno=%d (%s) off=%u/%u", errno, strerror(errno),
                     (unsigned)off, (unsigned)len);
            return -1;
        }
        if (n == 0) {
            ESP_LOGE(NET_TAG, "peer menutup koneksi off=%u/%u", (unsigned)off, (unsigned)len);
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* Frame: 4-byte big-endian length + payload */
static inline int send_frame(int s, const uint8_t *p, uint32_t len) {
    uint8_t h[4] = { (uint8_t)(len >> 24), (uint8_t)(len >> 16),
                     (uint8_t)(len >> 8),  (uint8_t)len };
    ESP_LOGI(NET_TAG, "TX frame len=%u hdr=%02x%02x%02x%02x",
             (unsigned)len, h[0], h[1], h[2], h[3]);
    if (send_all(s, h, 4) != 0) return -1;
    return send_all(s, p, len);
}

static inline int recv_frame(int s, uint8_t *buf, uint32_t max, uint32_t *out_len) {
    uint8_t h[4];
    if (recv_all(s, h, 4) != 0) return -1;
    uint32_t len = ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) |
                   ((uint32_t)h[2] << 8)  | (uint32_t)h[3];
    ESP_LOGI(NET_TAG, "RX hdr=%02x%02x%02x%02x len=%u", h[0], h[1], h[2], h[3], (unsigned)len);
    if (len > max) { ESP_LOGE(NET_TAG, "frame %u > buffer %u", (unsigned)len, (unsigned)max); return -2; }
    if (recv_all(s, buf, len) != 0) return -1;
    *out_len = len;
    return 0;
}
