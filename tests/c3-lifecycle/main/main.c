// SPDX-License-Identifier: Apache-2.0
#include "esp_frp.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum { WARMUP_CYCLES = 10, TEST_CYCLES = 100, HEAP_TOLERANCE_BYTES = 512 };

static bool time_untrusted(void *context)
{
    (void)context;
    return false;
}

static bool run_cycle(unsigned cycle)
{
    /* The worker must reject the clock before opening DNS, TCP or TLS. */
    static const uint8_t ca[] = "invalid-lab-ca";
    static const uint8_t token[] = "lab-token";
    const efrp_config_t config = {
        .server_hostname = "frp.example.invalid", .server_port = 7000,
        .ca_pem = ca, .ca_length = sizeof ca - 1,
        .token = token, .token_length = sizeof token - 1,
        .hostname = "c3-lifecycle", .client_id = "c3-lifecycle",
        .proxy_name = "c3-lifecycle", .local_ipv4 = {127, 0, 0, 1}, .local_port = 8765,
        .time_is_trusted = time_untrusted,
    };
    efrp_client_t *client = NULL;
    efrp_status_t status = {0};
    efrp_result_t result = efrp_create(&config, &client);
    if (result != EFRP_OK || !client) goto fail;
    result = efrp_start(client);
    if (result != EFRP_OK) goto fail;
    const int64_t deadline_us = esp_timer_get_time() + 5000000;
    do {
        result = efrp_get_status(client, &status);
        if (result != EFRP_OK) goto fail;
        if (status.phase == EFRP_PHASE_FAILED) break;
        vTaskDelay(1);
    } while (esp_timer_get_time() < deadline_us);
    if (status.phase != EFRP_PHASE_FAILED || status.error != EFRP_TIME_UNTRUSTED ||
        status.attempts != 1 || status.retries || status.ready_sessions) goto fail;
    result = efrp_stop(client, 5000);
    if (result != EFRP_OK) goto fail;
    result = efrp_get_status(client, &status);
    if (result != EFRP_OK || status.phase != EFRP_PHASE_STOPPED ||
        status.work.active || status.work.waiting) goto fail;
    result = efrp_destroy(&client, 5000);
    if (result != EFRP_OK || client) goto fail;
    return true;
fail:
    printf("EFRP_C3_LIFECYCLE fail cycle=%u result=%d phase=%d error=%d attempts=%" PRIu64
           " retries=%" PRIu64 " ready=%" PRIu64 "\n", cycle, result, status.phase,
           status.error, status.attempts, status.retries, status.ready_sessions);
    if (client) (void)efrp_destroy(&client, 5000);
    return false;
}

void app_main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("ESP_FRP_LAB_ONLY C3_LIFECYCLE sdk=6.1 target=esp32c3");
    size_t baseline = 0, lowest = SIZE_MAX;
    for (unsigned cycle = 0; cycle < WARMUP_CYCLES + TEST_CYCLES; ++cycle) {
        if (!run_cycle(cycle)) abort();
        if (cycle == WARMUP_CYCLES - 1) baseline = heap_caps_get_free_size(MALLOC_CAP_8BIT);
        if (cycle >= WARMUP_CYCLES) {
            size_t free_bytes = heap_caps_get_free_size(MALLOC_CAP_8BIT);
            if (free_bytes < lowest) lowest = free_bytes;
            if (free_bytes + HEAP_TOLERANCE_BYTES < baseline) {
                printf("EFRP_C3_LIFECYCLE heap_loss cycle=%u baseline=%zu free=%zu\n",
                       cycle, baseline, free_bytes);
                abort();
            }
        }
    }
    printf("EFRP_C3_LIFECYCLE PASS cycles=%u warmup=%u baseline=%zu lowest=%zu final=%zu"
           " largest=%zu\n", TEST_CYCLES, WARMUP_CYCLES, baseline, lowest,
           heap_caps_get_free_size(MALLOC_CAP_8BIT),
           heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}
