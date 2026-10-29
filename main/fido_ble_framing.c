#include "fido_ble_framing.h"

#include <string.h>

enum {
    FIDO_BLE_CANCEL = 0xbe,
    FIDO_BLE_ERR_INVALID_LEN = 0x03,
    FIDO_BLE_ERR_INVALID_SEQ = 0x04,
    FIDO_BLE_ERR_BUSY = 0x06,
};

static fido_ble_fragment_outcome outcome(fido_ble_fragment_result result,
                                         uint8_t command, uint8_t error)
{
    fido_ble_fragment_outcome value = {result, command, error};
    return value;
}

void fido_ble_reassembly_reset(fido_ble_reassembly *state)
{
    state->size = 0;
    state->used = 0;
    state->started_ms = 0;
    state->command = 0;
    state->sequence = 0;
    state->active = false;
}

fido_ble_fragment_outcome fido_ble_receive_fragment(
    fido_ble_reassembly *state, const uint8_t *fragment, uint16_t length,
    uint32_t now_ms)
{
    if (!length) {
        return outcome(FIDO_BLE_FRAGMENT_ERROR, 0,
                       FIDO_BLE_ERR_INVALID_LEN);
    }
    if (fragment[0] & 0x80u) {
        if (length < 3u) {
            return outcome(FIDO_BLE_FRAGMENT_ERROR, fragment[0],
                           FIDO_BLE_ERR_INVALID_LEN);
        }
        uint16_t total = (uint16_t)(((uint16_t)fragment[1] << 8) |
                                    fragment[2]);
        uint16_t supplied = (uint16_t)(length - 3u);
        if (total > FIDO_BLE_MESSAGE_CAP || supplied > total) {
            return outcome(FIDO_BLE_FRAGMENT_ERROR, fragment[0],
                           FIDO_BLE_ERR_INVALID_LEN);
        }
        if (state->active && fragment[0] != FIDO_BLE_CANCEL) {
            return outcome(FIDO_BLE_FRAGMENT_ERROR, fragment[0],
                           FIDO_BLE_ERR_BUSY);
        }
        fido_ble_reassembly_reset(state);
        state->command = fragment[0];
        state->size = total;
        state->used = supplied;
        state->started_ms = now_ms;
        state->active = supplied != total;
        if (supplied) {
            memcpy(state->data, fragment + 3, supplied);
        }
        return outcome(state->active ? FIDO_BLE_FRAGMENT_MORE
                                     : FIDO_BLE_FRAGMENT_COMPLETE,
                       state->command, 0);
    }
    if (!state->active || fragment[0] != state->sequence) {
        fido_ble_reassembly_reset(state);
        return outcome(FIDO_BLE_FRAGMENT_ERROR, 0,
                       FIDO_BLE_ERR_INVALID_SEQ);
    }
    uint16_t supplied = (uint16_t)(length - 1u);
    uint16_t remaining = (uint16_t)(state->size - state->used);
    if (supplied > remaining) {
        fido_ble_reassembly_reset(state);
        return outcome(FIDO_BLE_FRAGMENT_ERROR, 0,
                       FIDO_BLE_ERR_INVALID_LEN);
    }
    if (supplied) {
        memcpy(state->data + state->used, fragment + 1, supplied);
    }
    state->used = (uint16_t)(state->used + supplied);
    state->sequence = (uint8_t)((state->sequence + 1u) & 0x7fu);
    if (state->used == state->size) {
        state->active = false;
        return outcome(FIDO_BLE_FRAGMENT_COMPLETE, state->command, 0);
    }
    return outcome(FIDO_BLE_FRAGMENT_MORE, state->command, 0);
}

bool fido_ble_reassembly_timed_out(const fido_ble_reassembly *state,
                                  uint32_t now_ms, uint32_t timeout_ms)
{
    return state->active && (uint32_t)(now_ms - state->started_ms) >= timeout_ms;
}

bool fido_ble_emit_frame(uint8_t command, const uint8_t *data,
                         uint16_t length, uint16_t fragment_capacity,
                         fido_ble_emit_fragment emit, void *context)
{
    if (fragment_capacity < 3u || fragment_capacity > 512u || emit == 0 ||
        length > FIDO_BLE_MESSAGE_CAP) {
        return false;
    }
    uint8_t fragment[512];
    uint16_t used = 0;
    uint16_t count = length;
    if (count > fragment_capacity - 3u) {
        count = (uint16_t)(fragment_capacity - 3u);
    }
    fragment[0] = command;
    fragment[1] = (uint8_t)(length >> 8);
    fragment[2] = (uint8_t)length;
    if (count) {
        memcpy(fragment + 3, data, count);
    }
    if (!emit(fragment, (uint16_t)(count + 3u), context)) {
        return false;
    }
    used = count;
    uint8_t sequence = 0;
    while (used < length) {
        count = (uint16_t)(length - used);
        if (count > fragment_capacity - 1u) {
            count = (uint16_t)(fragment_capacity - 1u);
        }
        fragment[0] = sequence;
        memcpy(fragment + 1, data + used, count);
        if (!emit(fragment, (uint16_t)(count + 1u), context)) {
            return false;
        }
        used = (uint16_t)(used + count);
        sequence = (uint8_t)((sequence + 1u) & 0x7fu);
    }
    return true;
}
