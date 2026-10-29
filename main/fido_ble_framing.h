#pragma once

#include <stdbool.h>
#include <stdint.h>

#define FIDO_BLE_MESSAGE_CAP 1200u

typedef struct {
    uint16_t size;
    uint16_t used;
    uint32_t started_ms;
    uint8_t command;
    uint8_t sequence;
    bool active;
    uint8_t data[FIDO_BLE_MESSAGE_CAP];
} fido_ble_reassembly;

typedef enum {
    FIDO_BLE_FRAGMENT_MORE,
    FIDO_BLE_FRAGMENT_COMPLETE,
    FIDO_BLE_FRAGMENT_ERROR,
} fido_ble_fragment_result;

typedef struct {
    fido_ble_fragment_result result;
    uint8_t command;
    uint8_t error;
} fido_ble_fragment_outcome;

typedef bool (*fido_ble_emit_fragment)(const uint8_t *fragment,
                                      uint16_t length, void *context);

void fido_ble_reassembly_reset(fido_ble_reassembly *state);
fido_ble_fragment_outcome fido_ble_receive_fragment(
    fido_ble_reassembly *state, const uint8_t *fragment, uint16_t length,
    uint32_t now_ms);
bool fido_ble_reassembly_timed_out(const fido_ble_reassembly *state,
                                  uint32_t now_ms, uint32_t timeout_ms);
bool fido_ble_emit_frame(uint8_t command, const uint8_t *data,
                         uint16_t length, uint16_t fragment_capacity,
                         fido_ble_emit_fragment emit, void *context);
