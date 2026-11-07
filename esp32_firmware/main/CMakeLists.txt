idf_component_register(SRCS "esp32_firmware.c" "slhdsa_smoke.c" "ina219.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES liboqs_hqc david-cermak__liboqs_mlkem liboqs_mldsa liboqs_slhdsa
                                  esp_wifi esp_netif nvs_flash esp_event lwip esp_timer esp_driver_i2c)
