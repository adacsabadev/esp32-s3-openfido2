#include "indicators.h"

#include "driver/gpio.h"
#include "esp_check.h"
#include "esp_timer.h"
#include "led_strip.h"
#include "log.h"

#define USER_BUTTON_GPIO GPIO_NUM_0
#define RGB_LED_GPIO GPIO_NUM_48
#define BUTTON_DEBOUNCE_MS 30
#define ACTIVITY_LED_MS 80
#define LED_LEVEL 4
#define RESULT_FLASH_COUNT 3
#define RESULT_PHASE_US 150000
#define WAITING_PHASE_US 250000
#define WINK_PHASE_US 300000
#define WINK_REPEAT_COUNT 3

typedef enum {
    LED_OFF,
    LED_WAITING,
    LED_SUCCESS,
    LED_FAILURE,
    LED_ACTIVITY,
    LED_WHITE,
} led_state;

static led_strip_handle_t led_strip;
static led_state current_led_state = LED_FAILURE;
static int stable_button_level = 1;
static int candidate_button_level = 1;
static int64_t candidate_since_us;
static int64_t activity_until_us;
static led_state result_state = LED_OFF;
static int64_t result_started_us;
static int64_t waiting_started_us;
static bool presence_active;
static bool presence_armed;
static bool presence_approved;
static bool wink_active;
static int64_t wink_started_us;

static void set_led(led_state state)
{
    if (current_led_state == state || led_strip == NULL) {
        return;
    }

    uint8_t red = 0;
    uint8_t green = 0;
    uint8_t blue = 0;
    switch (state) {
    case LED_WAITING:
        red = LED_LEVEL;
        blue = LED_LEVEL;
        break;
    case LED_SUCCESS:
        green = LED_LEVEL;
        break;
    case LED_FAILURE:
        red = LED_LEVEL;
        break;
    case LED_ACTIVITY:
        blue = LED_LEVEL;
        break;
    case LED_WHITE:
        red = green = blue = LED_LEVEL;
        break;
    case LED_OFF:
        break;
    }

    ESP_ERROR_CHECK(led_strip_set_pixel(led_strip, 0, red, green, blue));
    ESP_ERROR_CHECK(led_strip_refresh(led_strip));
    current_led_state = state;
}

void indicators_init(void)
{
    const gpio_config_t button_config = {
        .pin_bit_mask = 1ULL << USER_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&button_config));

    const led_strip_config_t strip_config = {
        .strip_gpio_num = RGB_LED_GPIO,
        .max_leds = 1,
        .led_model = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .flags.invert_out = false,
    };
    const led_strip_rmt_config_t rmt_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,
        .mem_block_symbols = 64,
        .flags.with_dma = false,
    };
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config,
                                              &led_strip));

    stable_button_level = gpio_get_level(USER_BUTTON_GPIO);
    candidate_button_level = stable_button_level;
    candidate_since_us = esp_timer_get_time();
    set_led(LED_OFF);
}

void indicators_poll(void)
{
    int64_t now_us = esp_timer_get_time();
    int level = gpio_get_level(USER_BUTTON_GPIO);

    if (level != candidate_button_level) {
        candidate_button_level = level;
        candidate_since_us = now_us;
    } else if (stable_button_level != candidate_button_level &&
               now_us - candidate_since_us >= BUTTON_DEBOUNCE_MS * 1000) {
        stable_button_level = candidate_button_level;
        if (presence_active) {
            if (stable_button_level != 0) {
                presence_armed = true;
            } else if (presence_armed) {
                presence_active = false;
                presence_approved = true;
                set_led(LED_OFF);
                log_puts("User presence approved\r\n");
            }
        }
    }

    if (result_state != LED_OFF) {
        int64_t phase = (now_us - result_started_us) / RESULT_PHASE_US;
        if (phase < RESULT_FLASH_COUNT * 2) {
            set_led((phase & 1) ? LED_OFF : result_state);
            return;
        }
        result_state = LED_OFF;
    }
    if (presence_active) {
        int64_t phase = (now_us - waiting_started_us) / WAITING_PHASE_US;
        set_led((phase & 1) ? LED_OFF : LED_WAITING);
    } else if (wink_active) {
        static const led_state phases[] = {
            LED_FAILURE, LED_WHITE, LED_SUCCESS, LED_OFF
        };
        int64_t phase = (now_us - wink_started_us) / WINK_PHASE_US;
        if (phase < 4 * WINK_REPEAT_COUNT) {
            set_led(phases[phase % 4]);
        } else {
            wink_active = false;
            set_led(LED_OFF);
        }
    } else if (now_us < activity_until_us) {
        set_led(LED_ACTIVITY);
    } else {
        set_led(LED_OFF);
    }
}

void indicators_activity(void)
{
    if (presence_active || result_state != LED_OFF || wink_active) {
        return;
    }
    activity_until_us = esp_timer_get_time() + ACTIVITY_LED_MS * 1000;
    set_led(LED_ACTIVITY);
}

void indicators_wink(void)
{
    /* Identification never consumes or grants a physical presence approval. */
    if (presence_active || presence_approved || result_state != LED_OFF) {
        return;
    }
    wink_started_us = esp_timer_get_time();
    wink_active = true;
    activity_until_us = 0;
    set_led(LED_FAILURE);
    log_puts("WINK: red, white, green\r\n");
}

void indicators_result(bool success)
{
    /* A transport error on another channel must not cancel a pending touch. */
    result_state = success ? LED_SUCCESS : LED_FAILURE;
    wink_active = false;
    result_started_us = esp_timer_get_time();
    activity_until_us = 0;
    set_led(result_state);
}

void presence_begin(void)
{
    wink_active = false;
    presence_active = true;
    presence_approved = false;
    result_state = LED_OFF;
    activity_until_us = 0;
    waiting_started_us = esp_timer_get_time();
    presence_armed = stable_button_level != 0 &&
                     candidate_button_level != 0 &&
                     gpio_get_level(USER_BUTTON_GPIO) != 0;
    set_led(LED_WAITING);
    log_puts("Waiting for a fresh BOOT-button press\r\n");
}

bool presence_take(void)
{
    if (!presence_approved) {
        return false;
    }
    presence_approved = false;
    return true;
}

void presence_cancel(void)
{
    presence_active = false;
    presence_armed = false;
    presence_approved = false;
    if (current_led_state == LED_WAITING) {
        set_led(LED_OFF);
    }
}
