#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
bool u2f_attestation_certificate(const uint8_t **certificate, size_t *length);
bool u2f_attestation_sign(const uint8_t *data, size_t length,
                          uint8_t signature[80], size_t *signature_length);
