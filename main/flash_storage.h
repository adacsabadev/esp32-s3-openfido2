#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FLASH_STORAGE_BANK_BYTES 0x00400000u

typedef enum {
    FLASH_STORAGE_JOURNAL,
    FLASH_STORAGE_SNAPSHOT
} flash_storage_region;

uint32_t flash_storage_region_start(flash_storage_region region);
size_t flash_storage_region_size(flash_storage_region region);
uint32_t flash_storage_address(flash_storage_region region, size_t offset);
bool flash_storage_validate_layout(void);
bool flash_storage_read(flash_storage_region region, size_t offset,
                        void *output, size_t length);
bool flash_storage_program(flash_storage_region region, size_t offset,
                           const void *data, size_t length);
bool flash_storage_erase(flash_storage_region region);
bool flash_storage_is_erased(flash_storage_region region, size_t offset,
                             size_t length);
