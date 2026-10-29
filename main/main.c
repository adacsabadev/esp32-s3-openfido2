#include "ble_fido.h"
#include "debug_console.h"
#include "fido2.h"
#include "flash_storage.h"
#include "indicators.h"
#include "log.h"
#include "platform.h"
#include "credential.h"
#include "pin_uv.h"
#include "usb_composite.h"

#include "bootloader_random.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "openfido2";

void app_main(void)
{
    bootloader_random_enable();
    platform_init();
    log_init();
    indicators_init();
    usb_composite_init();

    esp_err_t nvs_status = nvs_flash_init();
    if (nvs_status == ESP_ERR_NVS_NO_FREE_PAGES ||
        nvs_status == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_status = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs_status);

    if (!log_settings_init())
        log_puts("ERR debug setting could not be loaded; debug logging is off\r\n");

    if (!credential_storage_init() || !pin_uv_storage_init()) {
        ESP_LOGE(TAG, "Credential storage initialization failed");
        for (;;) {
            usb_composite_poll();
            platform_idle();
        }
    }

    fido2_init();
    ble_fido_init();
    log_puts("ESP32-S3 OpenFIDO2 initialized; research prototype only\r\n");

    for (;;) {
        indicators_poll();
        usb_composite_poll();
        debug_console_poll();
        fido2_poll();
        ble_fido_poll();
        platform_idle();
    }
}
