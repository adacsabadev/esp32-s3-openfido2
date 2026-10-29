#include "flash_storage.h"
#include "ctaphid.h"
#include "log.h"
#include "platform.h"
#include "esp_log.h"
#include "esp_partition.h"

#define STORAGE_LABEL "openfido"
#define STORAGE_ADDRESS 0x00800000u
#define STORAGE_BYTES (2u * FLASH_STORAGE_BANK_BYTES)
static const esp_partition_t *partition;
static const char *TAG = "credential_flash";

static bool valid_region(flash_storage_region region)
{
    return region == FLASH_STORAGE_JOURNAL || region == FLASH_STORAGE_SNAPSHOT;
}

bool flash_storage_validate_layout(void)
{
    if (!partition) partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t)0x40, STORAGE_LABEL);
    if (!partition || partition->address != STORAGE_ADDRESS ||
        partition->size != STORAGE_BYTES) {
        ESP_LOGE(TAG, "Expected 8 MiB credential partition at 0x800000");
        return false;
    }
    return true;
}

size_t flash_storage_region_size(flash_storage_region region)
{
    return valid_region(region) ? FLASH_STORAGE_BANK_BYTES : 0;
}

uint32_t flash_storage_region_start(flash_storage_region region)
{
    if (!valid_region(region) || !flash_storage_validate_layout()) return 0;
    return partition->address + (unsigned)region * FLASH_STORAGE_BANK_BYTES;
}

uint32_t flash_storage_address(flash_storage_region region, size_t offset)
{
    uint32_t base = flash_storage_region_start(region);
    return base && offset <= FLASH_STORAGE_BANK_BYTES ? base + offset : 0;
}

static bool valid_range(flash_storage_region region, size_t offset, size_t length)
{
    return valid_region(region) && offset <= FLASH_STORAGE_BANK_BYTES &&
        length <= FLASH_STORAGE_BANK_BYTES - offset && flash_storage_validate_layout();
}

bool flash_storage_read(flash_storage_region region, size_t offset,
                        void *output, size_t length)
{
    if (!output || !valid_range(region, offset, length)) {
        log_debug_printf("flash read rejected bank=%u offset=0x%08x bytes=%u",
                         (unsigned)region, (unsigned)offset, (unsigned)length);
        return false;
    }
    esp_err_t status = esp_partition_read(partition, (unsigned)region * FLASH_STORAGE_BANK_BYTES +
                                          offset, output, length);
    log_debug_printf("flash read bank=%u address=0x%08x bytes=%u result=%s",
                     (unsigned)region, flash_storage_address(region, offset),
                     (unsigned)length, status == ESP_OK ? "ok" : "failed");
    return status == ESP_OK;
}

bool flash_storage_program(flash_storage_region region, size_t offset,
                           const void *data, size_t length)
{
    if (!data || !length || offset % 4 || length % 4 ||
        !valid_range(region, offset, length)) {
        log_debug_printf("flash program rejected bank=%u offset=0x%08x bytes=%u",
                         (unsigned)region, (unsigned)offset, (unsigned)length);
        return false;
    }
    esp_err_t status = esp_partition_write(partition, (unsigned)region * FLASH_STORAGE_BANK_BYTES +
                                           offset, data, length);
    log_debug_printf("flash program bank=%u address=0x%08x bytes=%u result=%s",
                     (unsigned)region, flash_storage_address(region, offset),
                     (unsigned)length, status == ESP_OK ? "ok" : "failed");
    return status == ESP_OK;
}

bool flash_storage_erase(flash_storage_region region)
{
    if (!valid_range(region, 0, FLASH_STORAGE_BANK_BYTES)) {
        log_debug_printf("flash erase rejected bank=%u", (unsigned)region);
        return false;
    }
    log_debug_printf("flash erase begin bank=%u address=0x%08x bytes=%u",
                     (unsigned)region, flash_storage_region_start(region),
                     (unsigned)FLASH_STORAGE_BANK_BYTES);
    /* Bound each erase and yield between chunks to keep USB and idle tasks alive. */
    for (size_t offset = 0; offset < FLASH_STORAGE_BANK_BYTES; offset += 0x10000u) {
        esp_err_t status = esp_partition_erase_range(partition, (unsigned)region *
            FLASH_STORAGE_BANK_BYTES + offset, 0x10000u);
        log_debug_printf("flash erase sector bank=%u address=0x%08x bytes=65536 result=%s",
                         (unsigned)region, flash_storage_address(region, offset),
                         status == ESP_OK ? "ok" : "failed");
        if (status != ESP_OK) return false;
        ctaphid_processing_tick();
        platform_idle();
    }
    log_debug_printf("flash erase complete bank=%u result=ok", (unsigned)region);
    return true;
}

bool flash_storage_is_erased(flash_storage_region region, size_t offset, size_t length)
{
    uint8_t buffer[64];
    while (length) {
        size_t count = length < sizeof buffer ? length : sizeof buffer;
        if (!flash_storage_read(region, offset, buffer, count)) return false;
        for (size_t i = 0; i < count; i++) if (buffer[i] != 0xff) return false;
        offset += count;
        length -= count;
    }
    return true;
}
