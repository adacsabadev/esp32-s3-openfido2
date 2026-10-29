#pragma once
#include <stdint.h>
uint16_t ctap2_dispatch(const uint8_t *request, uint16_t request_length,
                        uint8_t *response, uint16_t response_capacity,uint32_t channel);
uint16_t ctap2_poll(uint8_t *response,uint16_t capacity);
void ctap2_cancel(void);
int ctap2_waiting(void);
