#include "usb_composite.h"

#include "class/hid/hid_device.h"
#include "ctaphid.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tusb.h"
#include "usb_descriptors.h"
#include "driver/uart.h"

#include <string.h>
#include <stdio.h>

#define FIDO_HID_REPORT_SIZE 64u
#define HID_TX_CAPACITY 32u
#define HID_RX_CAPACITY 8u
#define CDC_RX_CAPACITY 2048u
#define CDC_CHUNK_SIZE 64u
#define CONSOLE_UART UART_NUM_0
#define CONSOLE_UART_BAUD 115200
#define CONSOLE_UART_RX_CAPACITY 1024u
#define CONSOLE_UART_TX_CAPACITY 8192u

#define CONFIG_DESC_LEN (TUD_CONFIG_DESC_LEN + 32u)

static const tusb_desc_device_t usb_device_descriptor = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = 0xef,
    .bDeviceSubClass = 0x02,
    .bDeviceProtocol = 0x01,
    .bMaxPacketSize0 = 64,
    .idVendor = 0x1209,
    .idProduct = 0xf201,
    .bcdDevice = 0x0100,
    .iManufacturer = 1,
    .iProduct = 2,
    .iSerialNumber = 3,
    .bNumConfigurations = 1,
};

const uint8_t usb_fido_report_descriptor[] = {
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20,
    0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40,
    0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00,
    0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
};

const uint16_t usb_fido_report_descriptor_length =
    sizeof usb_fido_report_descriptor;

static const uint8_t usb_configuration_descriptor[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, CONFIG_DESC_LEN,
                          0x80, 100),
    9, TUSB_DESC_INTERFACE, 0, 0, 2, TUSB_CLASS_HID, 0, 0, 4,
    9, HID_DESC_TYPE_HID, 0x11, 0x01, 0, 1, HID_DESC_TYPE_REPORT,
    sizeof usb_fido_report_descriptor, 0,
    7, TUSB_DESC_ENDPOINT, 0x01, TUSB_XFER_INTERRUPT,
    FIDO_HID_REPORT_SIZE, 0, 5,
    7, TUSB_DESC_ENDPOINT, 0x81, TUSB_XFER_INTERRUPT,
    FIDO_HID_REPORT_SIZE, 0, 5,
};

static const char language_descriptor[] = {0x09, 0x04};
static const char *usb_string_descriptors[] = {
    language_descriptor,
    "OpenFIDO2 project",
    "ESP32-S3 OpenFIDO2",
    NULL,
    "FIDO2 HID",
};
static char usb_serial_number[13];

static uint8_t hid_tx[HID_TX_CAPACITY][FIDO_HID_REPORT_SIZE];
static uint8_t hid_rx[HID_RX_CAPACITY][FIDO_HID_REPORT_SIZE];
static uint8_t cdc_rx[CDC_RX_CAPACITY];
static size_t hid_tx_head;
static size_t hid_tx_tail;
static size_t hid_rx_head;
static size_t hid_rx_tail;
static size_t cdc_rx_head;
static size_t cdc_rx_tail;
static volatile uint32_t cdc_rx_overflow;
static volatile uint32_t hid_tx_dropped;
static volatile uint32_t hid_rx_dropped;
static uint32_t reported_cdc_rx_overflow;
static uint32_t reported_hid_tx_dropped;
static uint32_t reported_hid_rx_dropped;
static portMUX_TYPE queue_lock = portMUX_INITIALIZER_UNLOCKED;
static const char *TAG = "openfido_usb";

static size_t ring_next(size_t index, size_t capacity)
{
    return (index + 1u) % capacity;
}

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
    (void)instance;
    return usb_fido_report_descriptor;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type, uint8_t *buffer,
                               uint16_t requested_length)
{
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)requested_length;
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t buffer_size)
{
    if (instance == 0 && report_id == 0 &&
        report_type == HID_REPORT_TYPE_OUTPUT &&
        buffer_size == FIDO_HID_REPORT_SIZE) {
        usb_fido_hid_rx(buffer, buffer_size);
    }
}

void usb_composite_init(void)
{
    uint8_t mac[6];
    ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_STA));
    snprintf(usb_serial_number, sizeof usb_serial_number,
             "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3],
             mac[4], mac[5]);
    usb_string_descriptors[3] = usb_serial_number;

    const uart_config_t uart_config = {
        .baud_rate = CONSOLE_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_driver_install(CONSOLE_UART,
                                         CONSOLE_UART_RX_CAPACITY,
                                         CONSOLE_UART_TX_CAPACITY, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(CONSOLE_UART, &uart_config));
    /* ESP32-S3 DevKit UART0 is connected to the FTDI bridge on GPIO43/44. */
    ESP_ERROR_CHECK(uart_set_pin(CONSOLE_UART, 43, 44,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

    tinyusb_config_t config = TINYUSB_DEFAULT_CONFIG();
    config.descriptor.device = &usb_device_descriptor;
    config.descriptor.full_speed_config = usb_configuration_descriptor;
    config.descriptor.string = usb_string_descriptors;
    config.descriptor.string_count =
        sizeof usb_string_descriptors / sizeof usb_string_descriptors[0];
    ESP_ERROR_CHECK(tinyusb_driver_install(&config));
}

void usb_composite_poll(void)
{
    uint8_t report[FIDO_HID_REPORT_SIZE];
    bool have_report = false;

    portENTER_CRITICAL(&queue_lock);
    if (hid_rx_tail != hid_rx_head) {
        memcpy(report, hid_rx[hid_rx_tail], sizeof report);
        hid_rx_tail = ring_next(hid_rx_tail, HID_RX_CAPACITY);
        have_report = true;
    }
    portEXIT_CRITICAL(&queue_lock);

    if (have_report) {
        ctaphid_receive(report);
    }

    uint8_t uart_input[CDC_CHUNK_SIZE];
    int uart_count = uart_read_bytes(CONSOLE_UART, uart_input,
                                     sizeof uart_input, 0);
    if (uart_count > 0) {
        usb_cdc_rx(uart_input, (uint32_t)uart_count);
    }

    usb_composite_tx_poll();

    portENTER_CRITICAL(&queue_lock);
    uint32_t rx_overflow = cdc_rx_overflow;
    uint32_t hid_tx_lost = hid_tx_dropped;
    uint32_t hid_rx_lost = hid_rx_dropped;
    portEXIT_CRITICAL(&queue_lock);
    if (rx_overflow != reported_cdc_rx_overflow ||
        hid_tx_lost != reported_hid_tx_dropped ||
        hid_rx_lost != reported_hid_rx_dropped) {
        ESP_LOGW(TAG,
                 "UART queue drops: rx=%lu, HID tx=%lu rx=%lu",
                 (unsigned long)rx_overflow,
                 (unsigned long)hid_tx_lost, (unsigned long)hid_rx_lost);
        reported_cdc_rx_overflow = rx_overflow;
        reported_hid_tx_dropped = hid_tx_lost;
        reported_hid_rx_dropped = hid_rx_lost;
    }
}

void usb_composite_tx_poll(void)
{
    if (!tud_mounted()) {
        return;
    }

    uint8_t report[FIDO_HID_REPORT_SIZE];
    bool have_report = false;
    portENTER_CRITICAL(&queue_lock);
    if (hid_tx_tail != hid_tx_head) {
        memcpy(report, hid_tx[hid_tx_tail], sizeof report);
        have_report = true;
    }
    portEXIT_CRITICAL(&queue_lock);

    if (have_report && tud_hid_ready() &&
        tud_hid_report(0, report, sizeof report)) {
        portENTER_CRITICAL(&queue_lock);
        hid_tx_tail = ring_next(hid_tx_tail, HID_TX_CAPACITY);
        portEXIT_CRITICAL(&queue_lock);
    }

}

void usb_fido_hid_write(const uint8_t *report, uint32_t length)
{
    if (report == NULL || length != FIDO_HID_REPORT_SIZE) {
        return;
    }

    portENTER_CRITICAL(&queue_lock);
    size_t next = ring_next(hid_tx_head, HID_TX_CAPACITY);
    if (next != hid_tx_tail) {
        memcpy(hid_tx[hid_tx_head], report, FIDO_HID_REPORT_SIZE);
        hid_tx_head = next;
    } else {
        hid_tx_dropped++;
    }
    portEXIT_CRITICAL(&queue_lock);
}

void usb_fido_hid_rx(const uint8_t *report, uint32_t length)
{
    if (report == NULL || length != FIDO_HID_REPORT_SIZE) {
        return;
    }

    portENTER_CRITICAL(&queue_lock);
    size_t next = ring_next(hid_rx_head, HID_RX_CAPACITY);
    if (next != hid_rx_tail) {
        memcpy(hid_rx[hid_rx_head], report, FIDO_HID_REPORT_SIZE);
        hid_rx_head = next;
    } else {
        hid_rx_dropped++;
    }
    portEXIT_CRITICAL(&queue_lock);
}

void usb_cdc_write(const uint8_t *data, uint32_t length)
{
    if (data == NULL) {
        return;
    }

    uart_write_bytes(CONSOLE_UART, data, length);

}

void usb_cdc_rx(const uint8_t *data, uint32_t length)
{
    if (data == NULL) {
        return;
    }

    portENTER_CRITICAL(&queue_lock);
    for (uint32_t i = 0; i < length; i++) {
        size_t next = ring_next(cdc_rx_head, CDC_RX_CAPACITY);
        if (next == cdc_rx_tail) {
            cdc_rx_overflow++;
        } else {
            cdc_rx[cdc_rx_head] = data[i];
            cdc_rx_head = next;
        }
    }
    portEXIT_CRITICAL(&queue_lock);
}

bool usb_cdc_read(uint8_t *byte)
{
    if (byte == NULL) {
        return false;
    }

    portENTER_CRITICAL(&queue_lock);
    if (cdc_rx_tail == cdc_rx_head) {
        portEXIT_CRITICAL(&queue_lock);
        return false;
    }
    *byte = cdc_rx[cdc_rx_tail];
    cdc_rx_tail = ring_next(cdc_rx_tail, CDC_RX_CAPACITY);
    portEXIT_CRITICAL(&queue_lock);
    return true;
}

uint32_t usb_cdc_pending(void)
{
    uint32_t pending;

    portENTER_CRITICAL(&queue_lock);
    if (cdc_rx_head >= cdc_rx_tail) {
        pending = (uint32_t)(cdc_rx_head - cdc_rx_tail);
    } else {
        pending = (uint32_t)(CDC_RX_CAPACITY - cdc_rx_tail + cdc_rx_head);
    }
    portEXIT_CRITICAL(&queue_lock);
    return pending;
}

uint32_t usb_cdc_rx_dropped(void)
{
    return cdc_rx_overflow;
}

uint32_t usb_cdc_tx_dropped(void)
{
    return 0;
}
